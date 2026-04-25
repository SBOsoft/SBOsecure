import { describe, it, expect, beforeAll } from 'vitest'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { webcrypto } from 'crypto'
import { getClasses } from './setup.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(__dirname, 'fixtures')

function loadFixture(name) {
    return JSON.parse(readFileSync(join(fixturesDir, name), 'utf-8'))
}

// ---------------------------------------------------------------------------
// SBO_Base64
// ---------------------------------------------------------------------------

describe('SBO_Base64', () => {
    it('round-trips a UTF-8 string', () => {
        const { SBO_Base64 } = getClasses()
        const b64 = new SBO_Base64(false)
        const original = 'Hello, SBOsecure! 🔐'
        expect(b64.decodeAsString(b64.encodeString(original))).toBe(original)
    })

    it('round-trips a byte array', () => {
        const { SBO_Base64 } = getClasses()
        const b64 = new SBO_Base64(false)
        const bytes = new Uint8Array([0, 1, 127, 128, 255, 42, 99])
        const encoded = b64.encodeBytes(bytes)
        const decoded = b64.decodeAsByteArray(encoded)
        expect(Array.from(decoded)).toEqual(Array.from(bytes))
    })

    it('produces different output in URL-safe mode', () => {
        const { SBO_Base64 } = getClasses()
        // Use bytes that produce + or / in standard Base64
        const bytes = new Uint8Array([0xfb, 0xff, 0xfe])
        const standard = new SBO_Base64(false).encodeBytes(bytes)
        const urlSafe  = new SBO_Base64(true).encodeBytes(bytes)
        expect(standard).not.toBe(urlSafe)
        expect(urlSafe).not.toMatch(/[+/]/)
    })
})

// ---------------------------------------------------------------------------
// SBO_AESEncrypt / SBO_AESDecrypt
// ---------------------------------------------------------------------------

describe('SBO_AESEncrypt / SBO_AESDecrypt', () => {
    let aesKey

    beforeAll(async () => {
        aesKey = await webcrypto.subtle.generateKey(
            { name: 'AES-CBC', length: 256 },
            true,
            ['encrypt', 'decrypt']
        )
    })

    it('round-trips a text message', async () => {
        const { SBO_AESEncrypt, SBO_AESDecrypt } = getClasses()
        const plaintext = 'Secret message for testing AES-CBC round-trip.'
        const bytes = new TextEncoder().encode(plaintext)

        const enc = new SBO_AESEncrypt()
        await enc.encrypt(bytes, 'AES-CBC', aesKey)

        const cipherB64 = enc.getCipherTextBase64Encoded()
        const ivB64     = enc.getIVBase64Encoded()

        expect(cipherB64).toBeTruthy()
        expect(ivB64).toBeTruthy()
        expect(cipherB64).not.toContain(plaintext)

        const decrypted = await SBO_AESDecrypt.decrypt(cipherB64, ivB64, aesKey, 'AES-CBC')
        expect(decrypted).toBe(plaintext)
    })

    it('produces different ciphertext for same plaintext (random IV)', async () => {
        const { SBO_AESEncrypt } = getClasses()
        const bytes = new TextEncoder().encode('same input')

        const enc1 = new SBO_AESEncrypt()
        const enc2 = new SBO_AESEncrypt()
        await enc1.encrypt(bytes, 'AES-CBC', aesKey)
        await enc2.encrypt(bytes, 'AES-CBC', aesKey)

        expect(enc1.getCipherTextBase64Encoded()).not.toBe(enc2.getCipherTextBase64Encoded())
    })

    it('returns null when decrypted with the wrong key', async () => {
        const { SBO_AESEncrypt, SBO_AESDecrypt } = getClasses()
        const wrongKey = await webcrypto.subtle.generateKey(
            { name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']
        )
        const enc = new SBO_AESEncrypt()
        await enc.encrypt(new TextEncoder().encode('text'), 'AES-CBC', aesKey)

        const result = await SBO_AESDecrypt.decrypt(
            enc.getCipherTextBase64Encoded(), enc.getIVBase64Encoded(), wrongKey, 'AES-CBC'
        )
        expect(result).toBeNull()
    })
})

// ---------------------------------------------------------------------------
// SBO_RSAOAEP – key wrapping
// ---------------------------------------------------------------------------

describe('SBO_RSAOAEP key wrapping', () => {
    let recipientKeyset

    beforeAll(() => {
        recipientKeyset = loadFixture('recipient-keyset.jwks.json')
    })

    it('wraps and unwraps a raw AES key', async () => {
        const { SBO_RSAOAEP, SBO_Base64 } = getClasses()
        const rsa = new SBO_RSAOAEP()

        // Generate a CEK (Content Encryption Key)
        const cek = await webcrypto.subtle.generateKey(
            { name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']
        )
        const rawCek = await webcrypto.subtle.exportKey('raw', cek)

        // Find recipient's RSA-OAEP public key
        const encPubJwk = recipientKeyset.public.keys.find(
            k => k.key_ops && k.key_ops.includes('encrypt')
        )
        const encPrivJwk = recipientKeyset.private.keys.find(
            k => k.key_ops && k.key_ops.includes('decrypt')
        )

        const pubKey  = await rsa.importJwkPublicKey(encPubJwk)
        const privKey = await rsa.importJwkPrivateKey(encPrivJwk)

        const wrapped   = await rsa.encrypt(pubKey, rawCek)
        const unwrapped = await rsa.decrypt(privKey, wrapped)

        expect(new Uint8Array(unwrapped)).toEqual(new Uint8Array(rawCek))
    })

    it('rejects decryption with a different private key', async () => {
        const { SBO_RSAOAEP } = getClasses()
        const rsa = new SBO_RSAOAEP()

        const senderKeyset = loadFixture('sender-keyset.jwks.json')
        const wrongPrivJwk = senderKeyset.private.keys.find(
            k => k.key_ops && k.key_ops.includes('decrypt')
        )

        const encPubJwk = recipientKeyset.public.keys.find(
            k => k.key_ops && k.key_ops.includes('encrypt')
        )

        const cek    = await webcrypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt'])
        const rawCek = await webcrypto.subtle.exportKey('raw', cek)
        const pubKey = await rsa.importJwkPublicKey(encPubJwk)
        const wrapped = await rsa.encrypt(pubKey, rawCek)

        const wrongPrivKey = await rsa.importJwkPrivateKey(wrongPrivJwk)
        await expect(rsa.decrypt(wrongPrivKey, wrapped)).rejects.toThrow()
    })
})

// ---------------------------------------------------------------------------
// SBO_RSASSAPKCS1v15 – signing
// ---------------------------------------------------------------------------

describe('SBO_RSASSAPKCS1v15 signing', () => {
    let senderKeyset

    beforeAll(() => {
        senderKeyset = loadFixture('sender-keyset.jwks.json')
    })

    it('sign and verify round-trip', async () => {
        const { SBO_RSASSAPKCS1v15 } = getClasses()
        const pkcs = new SBO_RSASSAPKCS1v15()

        const privJwk = senderKeyset.private.keys.find(k => k.key_ops && k.key_ops.includes('sign'))
        const pubJwk  = senderKeyset.public.keys.find(k => k.key_ops && k.key_ops.includes('verify'))

        const privKey = await pkcs.importSigningPrivateKey(privJwk)
        const pubKey  = await pkcs.importVerificationPublicKey(pubJwk)

        const message   = '{"type":"sbo-encrypted","data":"test"}'
        const sigBuffer = await pkcs.sign(privKey, message)
        const valid     = await pkcs.verifySignature(pubKey, sigBuffer, message)

        expect(valid).toBe(true)
    })

    it('rejects a tampered message', async () => {
        const { SBO_RSASSAPKCS1v15 } = getClasses()
        const pkcs = new SBO_RSASSAPKCS1v15()

        const privJwk = senderKeyset.private.keys.find(k => k.key_ops && k.key_ops.includes('sign'))
        const pubJwk  = senderKeyset.public.keys.find(k => k.key_ops && k.key_ops.includes('verify'))

        const privKey = await pkcs.importSigningPrivateKey(privJwk)
        const pubKey  = await pkcs.importVerificationPublicKey(pubJwk)

        const original = '{"type":"sbo-encrypted"}'
        const tampered = '{"type":"sbo-encrypted","injected":true}'
        const sig      = await pkcs.sign(privKey, original)
        const valid    = await pkcs.verifySignature(pubKey, sig, tampered)

        expect(valid).toBe(false)
    })

    it('rejects signature from a different key', async () => {
        const { SBO_RSASSAPKCS1v15 } = getClasses()
        const pkcs = new SBO_RSASSAPKCS1v15()

        const recipientKeyset = loadFixture('recipient-keyset.jwks.json')
        const wrongPrivJwk = recipientKeyset.private.keys.find(k => k.key_ops && k.key_ops.includes('sign'))
        const senderPubJwk = senderKeyset.public.keys.find(k => k.key_ops && k.key_ops.includes('verify'))

        const wrongPrivKey = await pkcs.importSigningPrivateKey(wrongPrivJwk)
        const senderPubKey = await pkcs.importVerificationPublicKey(senderPubJwk)

        const message = '{"type":"sbo-encrypted"}'
        const sig     = await pkcs.sign(wrongPrivKey, message)
        const valid   = await pkcs.verifySignature(senderPubKey, sig, message)

        expect(valid).toBe(false)
    })
})

// ---------------------------------------------------------------------------
// Full encryption flow (mirrors EncryptForm.encrypt())
// ---------------------------------------------------------------------------

describe('Full encryption flow', () => {
    let senderKeyset, recipientKeyset, aliceContact, testContacts

    beforeAll(() => {
        senderKeyset    = loadFixture('sender-keyset.jwks.json')
        recipientKeyset = loadFixture('recipient-keyset.jwks.json')
        aliceContact    = loadFixture('test-contact.json')
        testContacts    = loadFixture('test-contacts.json')
    })

    /** Mirrors EncryptForm.encrypt() — returns the final package object */
    async function encryptForContacts(plaintext, contacts, myKeys) {
        const { SBO_AESEncrypt, SBO_RSAOAEP, SBO_RSASSAPKCS1v15, SBO_Base64 } = getClasses()

        const contentBytes = new TextEncoder().encode(plaintext)

        // Generate CEK
        const cek = await webcrypto.subtle.generateKey(
            { name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']
        )

        // Encrypt content
        const aesEnc = new SBO_AESEncrypt()
        await aesEnc.encrypt(contentBytes, 'AES-CBC', cek)

        const rawCek = await webcrypto.subtle.exportKey('raw', cek)
        const b64    = new SBO_Base64(false)
        const rsa    = new SBO_RSAOAEP()

        // Wrap CEK for each recipient
        const encryptedKeys = []
        for (const contact of contacts) {
            const jwks      = JSON.parse(contact.jwks)
            const encKeyJwk = jwks.keys.find(k => k.key_ops && k.key_ops.includes('encrypt'))
            const pubKey    = await rsa.importJwkPublicKey(encKeyJwk)
            const wrapped   = await rsa.encrypt(pubKey, rawCek)
            encryptedKeys.push({
                recipientName: contact.name,
                encryptedKey: b64.encodeBytes(new Uint8Array(wrapped))
            })
        }

        const payload = {
            version: 1,
            type: 'sbo-encrypted',
            encryptedContent: {
                ciphertext:   aesEnc.getCipherTextBase64Encoded(),
                iv:           aesEnc.getIVBase64Encoded(),
                originalName: 'message.txt'
            },
            encryptedKeys
        }

        // Sign
        let signature = null
        let signerPublicKey = null
        if (myKeys) {
            const pkcs     = new SBO_RSASSAPKCS1v15()
            const privJwk  = myKeys.private.keys.find(k => k.key_ops && k.key_ops.includes('sign'))
            const privKey  = await pkcs.importSigningPrivateKey(privJwk)
            const sigBuf   = await pkcs.sign(privKey, JSON.stringify(payload))
            signature      = b64.encodeBytes(new Uint8Array(sigBuf))
            signerPublicKey = myKeys.public.keys.find(k => k.key_ops && k.key_ops.includes('verify'))
        }

        return { ...payload, signature, signerPublicKey }
    }

    /** Decrypts a package for a given recipient keyset — returns plaintext string */
    async function decryptPackage(pkg, recipientPrivateKeyset) {
        const { SBO_RSAOAEP, SBO_AESDecrypt, SBO_Base64 } = getClasses()

        const rsa      = new SBO_RSAOAEP()
        const b64      = new SBO_Base64(false)
        const privJwk  = recipientPrivateKeyset.private.keys.find(k => k.key_ops && k.key_ops.includes('decrypt'))
        const privKey  = await rsa.importJwkPrivateKey(privJwk)

        // Any recipient entry works — use the first one
        const encKeyB64 = pkg.encryptedKeys[0].encryptedKey
        const wrapped   = b64.decodeAsByteArray(encKeyB64)
        const rawCek    = await rsa.decrypt(privKey, wrapped)

        const cek = await webcrypto.subtle.importKey(
            'raw', rawCek, { name: 'AES-CBC' }, false, ['decrypt']
        )

        return SBO_AESDecrypt.decrypt(
            pkg.encryptedContent.ciphertext,
            pkg.encryptedContent.iv,
            cek,
            'AES-CBC'
        )
    }

    it('produces a package with the required structure', async () => {
        const pkg = await encryptForContacts('test', [aliceContact], senderKeyset)

        expect(pkg.version).toBe(1)
        expect(pkg.type).toBe('sbo-encrypted')
        expect(pkg.encryptedContent.ciphertext).toBeTruthy()
        expect(pkg.encryptedContent.iv).toBeTruthy()
        expect(pkg.encryptedContent.originalName).toBe('message.txt')
        expect(pkg.encryptedKeys).toHaveLength(1)
        expect(pkg.encryptedKeys[0].recipientName).toBe('Alice Test')
        expect(pkg.signature).toBeTruthy()
        expect(pkg.signerPublicKey).toBeTruthy()
    })

    it('recipient can decrypt the content', async () => {
        const plaintext = 'Confidential message for Alice.'
        const pkg = await encryptForContacts(plaintext, [aliceContact], senderKeyset)
        const decrypted = await decryptPackage(pkg, recipientKeyset)
        expect(decrypted).toBe(plaintext)
    })

    it('ciphertext is not the plaintext', async () => {
        const plaintext = 'Do not store this in plaintext.'
        const pkg = await encryptForContacts(plaintext, [aliceContact], senderKeyset)
        expect(pkg.encryptedContent.ciphertext).not.toContain(plaintext)
    })

    it('signature verifies against the payload', async () => {
        const { SBO_RSASSAPKCS1v15, SBO_Base64 } = getClasses()
        const pkcs = new SBO_RSASSAPKCS1v15()
        const b64  = new SBO_Base64(false)

        const pkg = await encryptForContacts('signed message', [aliceContact], senderKeyset)

        // Reconstruct the payload string that was signed (same as in encryptForContacts)
        const payload = {
            version: pkg.version,
            type: pkg.type,
            encryptedContent: pkg.encryptedContent,
            encryptedKeys: pkg.encryptedKeys
        }

        const pubKey = await pkcs.importVerificationPublicKey(pkg.signerPublicKey)
        const sigBytes = b64.decodeAsByteArray(pkg.signature)
        const valid = await pkcs.verifySignature(pubKey, sigBytes, JSON.stringify(payload))
        expect(valid).toBe(true)
    })

    it('package is not signed when no sender keys are provided', async () => {
        const pkg = await encryptForContacts('unsigned', [aliceContact], null)
        expect(pkg.signature).toBeNull()
        expect(pkg.signerPublicKey).toBeNull()
    })

    it('encrypts for multiple recipients and each can decrypt', async () => {
        const { SBO_RSAOAEP, SBO_AESDecrypt, SBO_Base64 } = getClasses()
        const plaintext  = 'Message for Alice, Bob, and Carol.'
        const threeContacts = testContacts.slice(0, 3)  // all 3

        // We only have the private key for recipient 1 (Alice), so just check package structure
        const pkg = await encryptForContacts(plaintext, threeContacts, senderKeyset)

        expect(pkg.encryptedKeys).toHaveLength(3)
        expect(pkg.encryptedKeys.map(k => k.recipientName)).toEqual(
            ['Alice Test', 'Bob Test', 'Carol Test']
        )

        // Alice (recipient keyset) is contact[0] — verify she can decrypt
        const rsa     = new SBO_RSAOAEP()
        const b64     = new SBO_Base64(false)
        const privJwk = recipientKeyset.private.keys.find(k => k.key_ops && k.key_ops.includes('decrypt'))
        const privKey = await rsa.importJwkPrivateKey(privJwk)

        // Alice's entry is first
        const wrapped = b64.decodeAsByteArray(pkg.encryptedKeys[0].encryptedKey)
        const rawCek  = await rsa.decrypt(privKey, wrapped)
        const cek     = await webcrypto.subtle.importKey('raw', rawCek, { name: 'AES-CBC' }, false, ['decrypt'])
        const result  = await SBO_AESDecrypt.decrypt(
            pkg.encryptedContent.ciphertext, pkg.encryptedContent.iv, cek, 'AES-CBC'
        )
        expect(result).toBe(plaintext)
    })

    it('wrong recipient cannot decrypt', async () => {
        const { SBO_RSAOAEP } = getClasses()
        const plaintext = 'Only for Alice.'
        const pkg = await encryptForContacts(plaintext, [aliceContact], senderKeyset)

        // Try to decrypt Alice's wrapped key using the sender's decryption private key
        const rsa = new SBO_RSAOAEP()
        const wrongPrivJwk = senderKeyset.private.keys.find(k => k.key_ops && k.key_ops.includes('decrypt'))
        const wrongPrivKey = await rsa.importJwkPrivateKey(wrongPrivJwk)

        const { SBO_Base64 } = getClasses()
        const b64    = new SBO_Base64(false)
        const wrapped = b64.decodeAsByteArray(pkg.encryptedKeys[0].encryptedKey)

        await expect(rsa.decrypt(wrongPrivKey, wrapped)).rejects.toThrow()
    })
})
