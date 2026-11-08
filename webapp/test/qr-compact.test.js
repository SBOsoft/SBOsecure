import { describe, it, expect, beforeAll } from 'vitest'
import vm from 'vm'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { webcrypto } from 'crypto'
import { getClasses } from './setup.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const fixture = (name) => JSON.parse(readFileSync(join(__dirname, 'fixtures', name), 'utf-8'))

/** Deterministic pseudo-random bytes, so failures are reproducible */
function prng(seed) {
    let s = seed >>> 0
    return () => {
        s = (s * 1664525 + 1013904223) >>> 0
        return s >>> 24
    }
}
function randomBytes(rand, length) {
    const out = new Uint8Array(length)
    for (let i = 0; i < length; i++) out[i] = rand()
    return out
}

/** Renders a QR code to RGBA pixels, as a camera or image file would provide them */
function renderToImageData(qr, scale = 4, border = 4) {
    const size = (qr.size + border * 2) * scale
    const data = new Uint8ClampedArray(size * size * 4).fill(255)
    for (let y = 0; y < qr.size; y++) {
        for (let x = 0; x < qr.size; x++) {
            if (!qr.getModule(x, y)) continue
            for (let dy = 0; dy < scale; dy++) {
                for (let dx = 0; dx < scale; dx++) {
                    const px = ((y + border) * scale + dy) * size + (x + border) * scale + dx
                    data[px * 4] = data[px * 4 + 1] = data[px * 4 + 2] = 0
                }
            }
        }
    }
    return { data, width: size, height: size }
}

/** Scans parts in the given order, as the app's scanner does, and returns the reassembled text */
async function scan(parts) {
    const { SBO_QRAssembler } = getClasses()
    const asm = new SBO_QRAssembler()
    for (const p of parts) asm.add(p)
    return asm.result()
}

const jwkOf = (keys, op) => keys.find(k => k.key_ops && k.key_ops.includes(op))

let sender, recipient, alice, contacts

beforeAll(() => {
    sender = fixture('sender-keyset.jwks.json')
    recipient = fixture('recipient-keyset.jwks.json')
    alice = fixture('test-contact.json')
    contacts = fixture('test-contacts.json')
})

/** Builds a package exactly like EncryptForm.encrypt() and returns its JSON text */
async function makePackage({ content = 'x'.repeat(200), recipients = [alice], signed = true, withKeyIds = true,
    originalName = 'message.txt', contentType = 'text/plain' } = {}) {
    const { SBO_AESEncrypt, SBO_RSAOAEP, SBO_RSASSAPKCS1v15, SBO_Base64, SBO_CryptoUtils, SBO_AES_ALG_NAME } = getClasses()
    const b64 = new SBO_Base64(false)
    const cek = await webcrypto.subtle.generateKey({ name: SBO_AES_ALG_NAME, length: 256 }, true, ['encrypt', 'decrypt'])
    const enc = new SBO_AESEncrypt()
    const bytes = typeof content === 'string' ? new TextEncoder().encode(content) : content
    await enc.encrypt(bytes, SBO_AES_ALG_NAME, cek)
    const rawCek = await webcrypto.subtle.exportKey('raw', cek)
    const rsa = new SBO_RSAOAEP()
    const encryptedKeys = []
    for (const c of recipients) {
        const jwk = jwkOf(JSON.parse(c.jwks).keys, 'encrypt')
        const wrapped = await rsa.encrypt(await rsa.importJwkPublicKey(jwk), rawCek)
        const entry = { recipientName: c.name }
        if (withKeyIds) entry.keyId = await SBO_CryptoUtils.jwkThumbprint(jwk)
        entry.encryptedKey = b64.encodeBytes(new Uint8Array(wrapped))
        encryptedKeys.push(entry)
    }
    const encryptedContent = { ciphertext: enc.getCipherTextBase64Encoded(), iv: enc.getIVBase64Encoded() }
    if (originalName !== null) encryptedContent.originalName = originalName
    if (contentType !== null) encryptedContent.contentType = contentType
    const payload = { version: 1, type: 'sbo-encrypted', encryptedContent, encryptedKeys }
    let signature = null
    let signerPublicKey = null
    if (signed) {
        const pkcs = new SBO_RSASSAPKCS1v15()
        const key = await pkcs.importSigningPrivateKey(jwkOf(sender.private.keys, 'sign'))
        signature = b64.encodeBytes(new Uint8Array(await pkcs.sign(key, JSON.stringify(payload))))
        signerPublicKey = jwkOf(sender.public.keys, 'verify')
    }
    return JSON.stringify(Object.assign({}, payload, { signature, signerPublicKey }))
}

/** Verifies a package signature the way DecryptForm does, with the given verification key */
async function signatureValid(pkg, verifyJwk) {
    const { SBO_RSASSAPKCS1v15, SBO_Base64 } = getClasses()
    const payload = { version: pkg.version, type: pkg.type, encryptedContent: pkg.encryptedContent, encryptedKeys: pkg.encryptedKeys }
    const pkcs = new SBO_RSASSAPKCS1v15()
    const key = await pkcs.importVerificationPublicKey(verifyJwk)
    return pkcs.verifySignature(key, new SBO_Base64(false).decodeAsByteArray(pkg.signature), JSON.stringify(payload))
}

/** Decrypts a package with the recipient fixture's key and returns the content bytes */
async function decryptContent(pkg) {
    const { SBO_RSAOAEP, SBO_AESDecrypt, SBO_Base64, SBO_AES_ALG_NAME } = getClasses()
    const rsa = new SBO_RSAOAEP()
    const priv = await rsa.importJwkPrivateKey(jwkOf(recipient.private.keys, 'decrypt'))
    const rawCek = await rsa.decrypt(priv, new SBO_Base64(false).decodeAsByteArray(pkg.encryptedKeys[0].encryptedKey))
    const cek = await webcrypto.subtle.importKey('raw', rawCek, { name: SBO_AES_ALG_NAME }, false, ['decrypt'])
    const buf = await SBO_AESDecrypt.decryptAsBuffer(pkg.encryptedContent.ciphertext, pkg.encryptedContent.iv, cek, SBO_AES_ALG_NAME)
    return new Uint8Array(buf)
}

// ---------------------------------------------------------------------------
// Base45
// ---------------------------------------------------------------------------

describe('SBO_Base45', () => {
    it('matches the RFC 9285 examples', () => {
        const { SBO_Base45 } = getClasses()
        const enc = (s) => SBO_Base45.encode(new TextEncoder().encode(s))
        const dec = (s) => new TextDecoder().decode(SBO_Base45.decode(s))
        expect(enc('AB')).toBe('BB8')
        expect(enc('Hello!!')).toBe('%69 VD92EX0')
        expect(enc('base-45')).toBe('UJCLQE7W581')
        expect(dec('QED8WEX0')).toBe('ietf!')
    })

    it('round-trips random data of every length up to 400 bytes', () => {
        const { SBO_Base45 } = getClasses()
        const rand = prng(45)
        for (let len = 0; len <= 400; len++) {
            const bytes = randomBytes(rand, len)
            const text = SBO_Base45.encode(bytes)
            expect(text).toMatch(/^[0-9A-Z $%*+\-./:]*$/)
            expect(Array.from(SBO_Base45.decode(text))).toEqual(Array.from(bytes))
        }
        // Extremes: all zero and all 0xFF bytes
        for (const fill of [0, 255]) {
            const bytes = new Uint8Array(301).fill(fill)
            expect(Array.from(SBO_Base45.decode(SBO_Base45.encode(bytes)))).toEqual(Array.from(bytes))
        }
    })

    it('rejects damaged text instead of returning wrong bytes', () => {
        const { SBO_Base45 } = getClasses()
        expect(() => SBO_Base45.decode('ab8')).toThrow(/character/)   // lower case is not Base45
        expect(() => SBO_Base45.decode('BB8B')).toThrow(/length/)     // length 3n+1 is impossible
        expect(() => SBO_Base45.decode('GGW')).toThrow(/value/)       // 65536 does not fit in 2 bytes
        expect(() => SBO_Base45.decode('U6')).toThrow(/value/)        // 300 does not fit in 1 byte
    })
})

// ---------------------------------------------------------------------------
// Splitting compact data into codes
// ---------------------------------------------------------------------------

describe('SBO_QR.splitCompact', () => {
    it('produces alphanumeric-only codes that never end in a space, for any data size', async () => {
        const { SBO_QR, qrcodegen } = getClasses()
        const rand = prng(7)
        for (const len of [1, 2, 3, 815, 816, 817, 1633, 2500, 5000]) {
            const bytes = randomBytes(rand, len)
            const parts = await SBO_QR.splitCompact(bytes)
            expect(parts.length).toBe(Math.ceil(len / SBO_QR.COMPACT_CHUNK_BYTES))
            for (const part of parts) {
                expect(part).toMatch(/^SBOQR2\/[0-9A-F]{8}\/\d+\/\d+\/[0-9A-Z $%*+\-./:]*$/)
                // A reader that trims whitespace must not be able to lose data
                expect(part.trim()).toBe(part)
                // The encoder must store it in alphanumeric mode, not byte mode
                const segs = qrcodegen.QrSegment.makeSegments(part)
                expect(segs).toHaveLength(1)
                expect(segs[0].mode).toBe(qrcodegen.QrSegment.Mode.ALPHANUMERIC)
                // Same density limit as the JSON codes
                expect(SBO_QR.encode(part).version).toBeLessThanOrEqual(23)
            }
        }
    })
})

// ---------------------------------------------------------------------------
// Public keys
// ---------------------------------------------------------------------------

describe('Compact public key codes', () => {
    it('fit in one code and read back as the same keys', async () => {
        const { SBO_QR, SBO_QRCompact, SBO_CryptoUtils } = getClasses()
        const jwksText = JSON.stringify(recipient.public)
        const shown = await SBO_QR.encodeForDisplay(jwksText)
        expect(shown.compact).toBe(true)
        expect(shown.parts).toHaveLength(1)
        expect((await SBO_QR.split(jwksText)).length).toBe(2)   // the JSON format needed 2

        const decoded = JSON.parse(await scan(shown.parts))
        expect(SBO_QRCompact.canonicalJson(decoded)).toBe(SBO_QRCompact.canonicalJson(recipient.public))
        for (const op of ['verify', 'encrypt']) {
            expect(await SBO_CryptoUtils.jwkThumbprint(jwkOf(decoded.keys, op)))
                .toBe(await SBO_CryptoUtils.jwkThumbprint(jwkOf(recipient.public.keys, op)))
        }
    })

    it('carry the key name, including non-ASCII characters', async () => {
        const { SBO_QR, SBO_QRCompact } = getClasses()
        const shown = await SBO_QR.encodeForDisplay(JSON.stringify(recipient.public), { name: 'Serkan Özkan 🔑' })
        expect(shown.compact).toBe(true)
        const decoded = JSON.parse(await scan(shown.parts))
        expect(decoded.name).toBe('Serkan Özkan 🔑')
        expect(SBO_QRCompact.canonicalJson(JSON.parse(decoded.jwks))).toBe(SBO_QRCompact.canonicalJson(recipient.public))
    })

    it('cap long names at 100 characters without splitting a character', async () => {
        const { SBO_QR } = getClasses()
        const jwksText = JSON.stringify(recipient.public)
        // 99 letters followed by emoji: the cut falls right after the first emoji
        const longName = 'a'.repeat(99) + '😀'.repeat(300)
        const shown = await SBO_QR.encodeForDisplay(jwksText, { name: longName })
        expect(shown.compact).toBe(true)
        expect(shown.parts).toHaveLength(1)
        const decoded = JSON.parse(await scan(shown.parts))
        expect(decoded.name).toBe('a'.repeat(99) + '😀')
        expect(Array.from(decoded.name)).toHaveLength(SBO_QR.MAX_NAME_CHARS)

        expect(SBO_QR.limitName('Ayşe')).toBe('Ayşe')
        expect(SBO_QR.limitName('')).toBeUndefined()
        expect(SBO_QR.limitName(undefined)).toBeUndefined()
    })

    it('can still be imported with Web Crypto after decoding', async () => {
        const { SBO_QR, SBO_RSAOAEP, SBO_RSASSAPKCS1v15 } = getClasses()
        const decoded = JSON.parse(await scan((await SBO_QR.encodeForDisplay(JSON.stringify(recipient.public))).parts))
        await new SBO_RSAOAEP().importJwkPublicKey(jwkOf(decoded.keys, 'encrypt'))
        await new SBO_RSASSAPKCS1v15().importVerificationPublicKey(jwkOf(decoded.keys, 'verify'))
    })
})

// ---------------------------------------------------------------------------
// Encrypted packages
// ---------------------------------------------------------------------------

describe('Compact package codes', () => {
    it('leave out the signer key by default; the signature verifies with the matching contact key', async () => {
        const { SBO_QR, SBO_CryptoUtils } = getClasses()
        const text = await makePackage()
        const shown = await SBO_QR.encodeForDisplay(text)
        expect(shown.compact).toBe(true)
        expect(shown.signerKeyLeftOut).toBe(true)
        expect(shown.signerKeyOptional).toBe(true)
        expect(shown.parts).toHaveLength(1)                       // the JSON format needed 3
        expect((await SBO_QR.split(text)).length).toBe(3)

        const pkg = JSON.parse(await scan(shown.parts))
        const original = JSON.parse(text)
        expect(pkg.signerPublicKey).toBeNull()
        const signerJwk = jwkOf(sender.public.keys, 'verify')
        expect((await SBO_CryptoUtils.jwkThumbprint(signerJwk)).startsWith(pkg.signerKeyRef)).toBe(true)
        expect(pkg.signerKeyRef).toMatch(/^[0-9a-f]{16}$/)
        // Everything that is signed is unchanged
        for (const field of ['version', 'type', 'encryptedContent', 'encryptedKeys', 'signature']) {
            expect(JSON.stringify(pkg[field])).toBe(JSON.stringify(original[field]))
        }
        expect(await signatureValid(pkg, signerJwk)).toBe(true)
        expect(new TextDecoder().decode(await decryptContent(pkg))).toBe('x'.repeat(200))
    })

    it('rebuild the exact original JSON when the signer key is included', async () => {
        const { SBO_QR } = getClasses()
        const text = await makePackage()
        const shown = await SBO_QR.encodeForDisplay(text, { includeSignerKey: true })
        expect(shown.compact).toBe(true)
        expect(shown.signerKeyLeftOut).toBe(false)
        const decodedText = await scan(shown.parts)
        expect(decodedText).toBe(text)
        const pkg = JSON.parse(decodedText)
        expect(await signatureValid(pkg, pkg.signerPublicKey)).toBe(true)
    })

    it('handle unsigned, older (no keyId), multi-recipient, binary and non-ASCII packages exactly', async () => {
        const { SBO_QR } = getClasses()
        const variants = [
            await makePackage({ signed: false }),
            await makePackage({ withKeyIds: false }),
            await makePackage({ recipients: contacts.slice(0, 3), content: 'y'.repeat(1500) }),
            await makePackage({ content: randomBytes(prng(3), 2000), originalName: 'photo.png', contentType: 'image/png' }),
            await makePackage({ content: 'Merhaba dünya ğüşıöç 😀', originalName: 'şiir — taslak.txt' }),
            await makePackage({ originalName: null, contentType: null }),
            await makePackage({ contentType: 'application/octet-stream' })
        ]
        for (const text of variants) {
            for (const includeSignerKey of [true, false]) {
                const shown = await SBO_QR.encodeForDisplay(text, { includeSignerKey })
                expect(shown.compact).toBe(true)
                const original = JSON.parse(text)
                const pkg = JSON.parse(await scan(shown.parts))
                if (original.signature && !includeSignerKey) {
                    expect(pkg.signerPublicKey).toBeNull()
                    pkg.signerPublicKey = original.signerPublicKey
                    delete pkg.signerKeyRef
                }
                expect(JSON.stringify(pkg)).toBe(JSON.stringify(original))
                if (original.signature) expect(await signatureValid(pkg, jwkOf(sender.public.keys, 'verify'))).toBe(true)
            }
        }
    })

    it('are much smaller than the JSON codes', async () => {
        const { SBO_QR } = getClasses()
        const text = await makePackage({ content: 'z'.repeat(1000) })
        const json = await SBO_QR.split(text)
        const compactWithKey = await SBO_QR.encodeForDisplay(text, { includeSignerKey: true })
        const compact = await SBO_QR.encodeForDisplay(text)
        const chars = (parts) => parts.reduce((n, p) => n + p.length, 0)
        // Alphanumeric characters cost 5.5 bits, byte-mode characters 8
        expect(chars(compactWithKey.parts) * 5.5).toBeLessThan(chars(json) * 8 * 0.7)
        expect(chars(compact.parts) * 5.5).toBeLessThan(chars(json) * 8 * 0.6)
    })
})

// ---------------------------------------------------------------------------
// Password-encrypted packages
// ---------------------------------------------------------------------------

describe('Compact password package codes', () => {
    it('rebuild the exact JSON, which still decrypts with the password', async () => {
        const { SBO_QR, SBO_PBKDF2, SBO_AESEncrypt, SBO_AESDecrypt, SBO_Base64, SBO_CryptoUtils, SBO_AES_ALG_NAME } = getClasses()
        const b64 = new SBO_Base64(false)
        const salt = SBO_CryptoUtils.getRandomBytes(16)
        const key = await SBO_PBKDF2.generateKey('correct horse', salt, 1000, SBO_AES_ALG_NAME)
        const enc = new SBO_AESEncrypt()
        await enc.encrypt(new TextEncoder().encode('şifreli mesaj'), SBO_AES_ALG_NAME, key)
        const text = JSON.stringify({
            version: 1, type: 'sbo-pbkdf-encrypted',
            encryptedContent: { ciphertext: enc.getCipherTextBase64Encoded(), iv: enc.getIVBase64Encoded() },
            pbkdf: { salt: b64.encodeBytes(salt) }
        })
        const shown = await SBO_QR.encodeForDisplay(text)
        expect(shown.compact).toBe(true)
        const decoded = await scan(shown.parts)
        expect(decoded).toBe(text)
        const p = JSON.parse(decoded)
        const key2 = await SBO_PBKDF2.generateKey('correct horse', b64.decodeAsByteArray(p.pbkdf.salt), 1000, SBO_AES_ALG_NAME)
        expect(await SBO_AESDecrypt.decrypt(p.encryptedContent.ciphertext, p.encryptedContent.iv, key2, SBO_AES_ALG_NAME))
            .toBe('şifreli mesaj')
    })
})

// ---------------------------------------------------------------------------
// Anything the compact format cannot represent exactly falls back to JSON
// ---------------------------------------------------------------------------

describe('Fallback to the JSON format', () => {
    it('is used for data the compact format cannot represent exactly, which still reads back intact', async () => {
        const { SBO_QR, SBO_QRCompact } = getClasses()
        const pkg = JSON.parse(await makePackage())
        const withExtraField = JSON.stringify(Object.assign({}, pkg, { comment: 'added by another tool' }))
        const reordered = JSON.stringify({ type: pkg.type, version: pkg.version, encryptedContent: pkg.encryptedContent,
            encryptedKeys: pkg.encryptedKeys, signature: pkg.signature, signerPublicKey: pkg.signerPublicKey })
        // A 256-byte signature ends in "==" in standard base64; another tool might leave the padding out
        expect(pkg.signature.endsWith('==')).toBe(true)
        const unpadded = JSON.stringify(Object.assign({}, pkg, { signature: pkg.signature.replace(/=+$/, '') }))
        const keyWithKid = JSON.stringify({ keys: [Object.assign({ kid: 'k1' }, recipient.public.keys[0]), recipient.public.keys[1]] })
        const otherExponent = JSON.stringify({ keys: [Object.assign({}, recipient.public.keys[0], { e: 'Aw' })] })
        const unknownJson = JSON.stringify({ hello: 'world', n: [1, 2, 3] })
        const badSignerKey = JSON.stringify(Object.assign({}, pkg, { signerPublicKey: { kty: 'EC', crv: 'P-256' } }))

        for (const text of [withExtraField, reordered, unpadded, keyWithKid, otherExponent, unknownJson, badSignerKey]) {
            expect(await SBO_QRCompact.encode(text)).toBeNull()
            const shown = await SBO_QR.encodeForDisplay(text)
            expect(shown.compact).toBe(false)
            expect(JSON.parse(await scan(shown.parts))).toEqual(JSON.parse(text))
        }
    })
})

// ---------------------------------------------------------------------------
// Damaged or foreign compact codes are rejected, never misread
// ---------------------------------------------------------------------------

describe('Damaged compact codes', () => {
    it('are rejected when any single character is changed', async () => {
        const { SBO_QR, SBO_Base45 } = getClasses()
        const [part] = (await SBO_QR.encodeForDisplay(JSON.stringify(recipient.public))).parts
        const header = part.slice(0, part.lastIndexOf('/') + 1)
        const rand = prng(11)
        for (let trial = 0; trial < 200; trial++) {
            const pos = header.length + (rand() * 256 + rand()) % (part.length - header.length)
            const current = part[pos]
            const replacement = SBO_Base45.ALPHABET[(SBO_Base45.ALPHABET.indexOf(current) + 1 + rand() % 44) % 45]
            const damaged = part.slice(0, pos) + replacement + part.slice(pos + 1)
            await expect(scan([damaged])).rejects.toThrow()
        }
    })

    it('are rejected when truncated, extended or from an unknown format', async () => {
        const { SBO_QR, SBO_QRCompact, SBO_QRAssembler } = getClasses()
        const [part] = (await SBO_QR.encodeForDisplay(JSON.stringify(recipient.public))).parts
        await expect(scan([part.slice(0, -3)])).rejects.toThrow()
        await expect(scan([part + '000'])).rejects.toThrow()
        expect(() => new SBO_QRAssembler().add('SBOQR9/0123ABCD/1/1/ABC')).toThrow(/newer version/)
        expect(() => new SBO_QRAssembler().add('SBOQR2/0123abcd/1/1/ABC')).toThrow(/header/)
        expect(() => new SBO_QRAssembler().add('SBOQR2/0123ABCD/1/1/abc')).toThrow(/character/)

        // Valid Base45 and checksum, but bytes that are not a valid layout
        expect(() => SBO_QRCompact.decode(new Uint8Array([2, 1]))).toThrow(/Damaged/)
        expect(() => SBO_QRCompact.decode(new Uint8Array([9, 1, 0]))).toThrow(/newer version/)
        expect(() => SBO_QRCompact.decode(new Uint8Array([1, 2, 0]))).toThrow(/newer version/)
        expect(() => SBO_QRCompact.decode(new Uint8Array([1, 1, 0, 1, 1, 0xff, 0xff, 0xff, 0xff]))).toThrow(/Damaged/)
        const keyBytes = (await SBO_QRCompact.encode(JSON.stringify(recipient.public))).bytes
        expect(() => SBO_QRCompact.decode(new Uint8Array([...keyBytes, 0]))).toThrow(/extra data/)
    })

    it('cannot be mixed with JSON-format parts', async () => {
        const { SBO_QR, SBO_QRAssembler } = getClasses()
        const text = await makePackage({ recipients: contacts.slice(0, 3), content: 'q'.repeat(3000) })
        const compact = (await SBO_QR.encodeForDisplay(text)).parts
        const json = await SBO_QR.split(text)
        const asm = new SBO_QRAssembler()
        asm.add(compact[0])
        expect(() => asm.add(json[1])).toThrow(/different set/)
    })
})

// ---------------------------------------------------------------------------
// Signature check in the decrypt form for packages without the signer key
// ---------------------------------------------------------------------------

describe('DecryptForm signature check of compact packages', () => {
    /** Runs DecryptForm's methods on a plain object, with the given loaded keys and contacts */
    function makeDecryptForm(myKeys, myContacts) {
        const ctx = getClasses()
        if (!ctx.__ui) {
            ctx.SBO_FormatTimestampSeconds = (ts) => String(ts)
            vm.runInContext(readFileSync(join(__dirname, '../DocumentRoot/ui.js'), 'utf-8'), ctx)
            ctx.__ui = vm.runInContext('DecryptForm', ctx)
        }
        return Object.assign({}, ctx.__ui.methods, { myKeys, myContacts, signatureStatus: null, signer: null })
    }
    const senderAsContact = () => ({ name: 'Sender Test', jwks: JSON.stringify(sender.public) })

    it('is valid and names the contact when the sender is a contact', async () => {
        const { SBO_QR } = getClasses()
        const pkg = JSON.parse(await scan((await SBO_QR.encodeForDisplay(await makePackage())).parts))
        const form = makeDecryptForm([], [alice, senderAsContact()])
        await form.verifySignature(pkg)
        expect(form.signatureStatus).toBe('valid')
        expect(form.signer.matchedContactName).toBe('Sender Test')
    })

    it('is valid and recognises the user when they signed it themselves', async () => {
        const { SBO_QR } = getClasses()
        const pkg = JSON.parse(await scan((await SBO_QR.encodeForDisplay(await makePackage())).parts))
        const form = makeDecryptForm([{ downloadable: { name: 'My key', created: 1 }, jwks: sender }], [])
        await form.verifySignature(pkg)
        expect(form.signatureStatus).toBe('valid')
        expect(form.signer.matchedKeyName).toBe('My key')
    })

    it('reports an unknown signer, not "unsigned" or "valid", when the sender is not a contact', async () => {
        const { SBO_QR } = getClasses()
        const pkg = JSON.parse(await scan((await SBO_QR.encodeForDisplay(await makePackage())).parts))
        const form = makeDecryptForm([], [alice])
        await form.verifySignature(pkg)
        expect(form.signatureStatus).toBe('unknown-signer')
        expect(form.signer).toBeNull()
    })

    it('reports invalid when the content was changed, even with the right contact', async () => {
        const { SBO_QR } = getClasses()
        const pkg = JSON.parse(await scan((await SBO_QR.encodeForDisplay(await makePackage())).parts))
        pkg.encryptedKeys[0].recipientName = 'Mallory'
        const form = makeDecryptForm([], [senderAsContact()])
        await form.verifySignature(pkg)
        expect(form.signatureStatus).toBe('invalid')
    })

    it('cannot be fooled by pointing the reference at another contact', async () => {
        const { SBO_QR, SBO_CryptoUtils } = getClasses()
        const pkg = JSON.parse(await scan((await SBO_QR.encodeForDisplay(await makePackage())).parts))
        // An attacker re-labels the package as signed by Alice; Alice's key cannot verify the sender's signature
        pkg.signerKeyRef = (await SBO_CryptoUtils.jwkThumbprint(jwkOf(JSON.parse(alice.jwks).keys, 'verify'))).slice(0, 16)
        const form = makeDecryptForm([], [alice, senderAsContact()])
        await form.verifySignature(pkg)
        expect(form.signatureStatus).toBe('invalid')
    })

    it('applies only the latest check when checks overlap', async () => {
        const { SBO_QR } = getClasses()
        const pkg = JSON.parse(await scan((await SBO_QR.encodeForDisplay(await makePackage())).parts))
        const form = makeDecryptForm([], [senderAsContact()])

        // A check is overtaken by a newer one (e.g. contacts changed): the older result is dropped
        const older = form.verifySignature(pkg)
        form.myContacts = []
        const newer = form.verifySignature(pkg)
        await Promise.all([older, newer])
        expect(form.signatureStatus).toBe('unknown-signer')

        // A reset for a different package cancels a check that is still running
        form.myContacts = [senderAsContact()]
        const pending = form.verifySignature(pkg)
        form.resetResult()
        await pending
        expect(form.signatureStatus).toBeNull()
        expect(form.signer).toBeNull()
    })

    it('updates status and signer together', async () => {
        const { SBO_QR } = getClasses()
        const pkg = JSON.parse(await scan((await SBO_QR.encodeForDisplay(await makePackage())).parts))
        const form = makeDecryptForm([], [senderAsContact()])
        await form.verifySignature(pkg)
        const previousSigner = form.signer

        // While a re-check runs, the previous result stays visible instead of being cleared
        const recheck = form.verifySignature(pkg)
        expect(form.signatureStatus).toBe('valid')
        expect(form.signer).toBe(previousSigner)
        await recheck
        expect(form.signatureStatus).toBe('valid')
        expect(form.signer.matchedContactName).toBe('Sender Test')
    })

    it('still verifies packages that include the signer key, with or without contacts', async () => {
        const { SBO_QR } = getClasses()
        const text = await makePackage()
        const pkg = JSON.parse(await scan((await SBO_QR.encodeForDisplay(text, { includeSignerKey: true })).parts))
        const form = makeDecryptForm([], [])
        await form.verifySignature(pkg)
        expect(form.signatureStatus).toBe('valid')
        expect(form.signer.matchedContactName).toBeNull()
    })
})

// ---------------------------------------------------------------------------
// End to end through real QR images
// ---------------------------------------------------------------------------

describe('Compact codes through rendered QR images', () => {
    it('a multi-part package survives encode, render, jsQR decode and reassembly in any order', async () => {
        const { SBO_QR, SBO_QRAssembler } = getClasses()
        const text = await makePackage({ recipients: contacts.slice(0, 3), content: 'Ö'.repeat(900), originalName: 'çok gizli.txt' })
        const shown = await SBO_QR.encodeForDisplay(text, { includeSignerKey: true })
        expect(shown.parts.length).toBeGreaterThan(1)

        const asm = new SBO_QRAssembler()
        for (let i = shown.parts.length - 1; i >= 0; i--) {
            const decoded = SBO_QR.decodeImageData(renderToImageData(SBO_QR.encode(shown.parts[i])), false)
            expect(decoded).toEqual([shown.parts[i]])
            asm.add(decoded[0])
        }
        expect(await asm.result()).toBe(text)
    })

    it('a public key with a name survives the image round trip', async () => {
        const { SBO_QR } = getClasses()
        const shown = await SBO_QR.encodeForDisplay(JSON.stringify(sender.public), { name: 'Ayşe' })
        const decoded = SBO_QR.decodeImageData(renderToImageData(SBO_QR.encode(shown.parts[0])), true)
        expect(JSON.parse(await scan(decoded)).name).toBe('Ayşe')
    })
})
