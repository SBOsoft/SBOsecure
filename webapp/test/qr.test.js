import { describe, it, expect } from 'vitest'
import vm from 'vm'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { getClasses } from './setup.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(__dirname, 'fixtures')

/** Builds a test string of the given length out of base64-like characters */
function makeText(length) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    let s = ''
    for (let i = 0; i < length; i++) s += alphabet[(i * 7 + 3) % alphabet.length]
    return s
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

// ---------------------------------------------------------------------------
// Splitting
// ---------------------------------------------------------------------------

describe('SBO_QR.split', () => {
    it('puts small data in a single part with a 1/1 header', async () => {
        const { SBO_QR } = getClasses()
        const parts = await SBO_QR.split('{"keys":[]}')
        expect(parts).toHaveLength(1)
        expect(parts[0]).toMatch(/^SBOQR1\/[0-9a-f]{8}\/1\/1\/\{"keys":\[\]\}$/)
    })

    it('splits larger data into parts of roughly equal size', async () => {
        const { SBO_QR } = getClasses()
        const parts = await SBO_QR.split(makeText(2000))
        expect(parts).toHaveLength(3)
        const sizes = []
        for (const p of parts) sizes.push(SBO_QR.parsePart(p).data.length)
        expect(Math.max(...sizes) - Math.min(...sizes)).toBeLessThanOrEqual(1)
        for (const p of parts) expect(SBO_QR.byteLength(p)).toBeLessThan(SBO_QR.CHUNK_BYTES + 40)
    })

    it('never splits a multi-byte character', async () => {
        const { SBO_QR } = getClasses()
        const text = 'Ş😀ğ'.repeat(400)
        const parts = await SBO_QR.split(text)
        expect(parts.length).toBeGreaterThan(1)
        let joined = ''
        for (const p of parts) {
            const data = SBO_QR.parsePart(p).data
            // A lone surrogate would mean a character was cut in half
            expect(data).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/)
            joined += data
        }
        expect(joined).toBe(text)
    })

    it('refuses data above the display limit', async () => {
        const { SBO_QR } = getClasses()
        expect(SBO_QR.canDisplay(makeText(SBO_QR.MAX_DISPLAY_BYTES))).toBe(true)
        expect(SBO_QR.canDisplay(makeText(SBO_QR.MAX_DISPLAY_BYTES + 1))).toBe(false)
        await expect(SBO_QR.split(makeText(SBO_QR.MAX_DISPLAY_BYTES + 1))).rejects.toThrow()
        await expect(SBO_QR.split('')).rejects.toThrow()
    })
})

// ---------------------------------------------------------------------------
// ASCII-only encoding of JSON
// ---------------------------------------------------------------------------

describe('SBO_QR.toAsciiSafe', () => {
    it('escapes non-ASCII characters in JSON so it parses to the same value', () => {
        const { SBO_QR } = getClasses()
        const original = JSON.stringify({ recipientName: 'Serkan Özkan', note: 'şğü 😀', n: 1 })
        const safe = SBO_QR.toAsciiSafe(original)
        expect(safe).toMatch(/^[\x00-\x7f]*$/)
        expect(JSON.parse(safe)).toEqual(JSON.parse(original))
        // Signatures are verified over JSON.stringify of the parsed package, which is unchanged
        expect(JSON.stringify(JSON.parse(safe))).toBe(original)
    })

    it('leaves ASCII text and non-JSON text unchanged', () => {
        const { SBO_QR } = getClasses()
        expect(SBO_QR.toAsciiSafe('{"a":"b"}')).toBe('{"a":"b"}')
        expect(SBO_QR.toAsciiSafe('not json: Özkan')).toBe('not json: Özkan')
    })

    it('splits JSON into ASCII-only parts and counts the escaped size against the limit', async () => {
        const { SBO_QR, SBO_QRAssembler } = getClasses()
        const original = JSON.stringify({ name: 'Ö'.repeat(1500) })
        expect(SBO_QR.encodedLength(original)).toBeGreaterThan(SBO_QR.byteLength(original))

        const parts = await SBO_QR.split(original)
        const asm = new SBO_QRAssembler()
        for (const p of parts) {
            expect(p).toMatch(/^[\x00-\x7f]*$/)
            asm.add(p)
        }
        expect(JSON.parse(await asm.result())).toEqual(JSON.parse(original))

        // 1,750 characters of 'Ö' is 3.5 KB as UTF-8 but 10.5 KB escaped: over the display limit
        const big = JSON.stringify({ name: 'Ö'.repeat(1750) })
        expect(SBO_QR.byteLength(big)).toBeLessThan(SBO_QR.MAX_DISPLAY_BYTES)
        expect(SBO_QR.canDisplay(big)).toBe(false)
    })
})

// ---------------------------------------------------------------------------
// Decoding worker
// ---------------------------------------------------------------------------

describe('qr-worker.js', () => {
    /** Loads the worker script in its own VM context with a minimal worker environment */
    function loadWorker() {
        const docRoot = join(__dirname, '../DocumentRoot')
        const posted = []
        const ctx = vm.createContext({ console })
        ctx.self = ctx
        ctx.postMessage = (msg) => posted.push(msg)
        ctx.importScripts = (path) => vm.runInContext(readFileSync(join(docRoot, path), 'utf-8'), ctx)
        vm.runInContext(readFileSync(join(docRoot, 'qr-worker.js'), 'utf-8'), ctx)
        return { ctx, posted }
    }

    it('decodes a code and answers with the request id', async () => {
        const { SBO_QR } = getClasses()
        const { ctx, posted } = loadWorker()
        const [part] = await SBO_QR.split('{"keys":["worker test"]}')
        const img = renderToImageData(SBO_QR.encode(part))

        ctx.onmessage({ data: { id: 7, data: img.data, width: img.width, height: img.height, thorough: false } })
        expect(posted).toEqual([{ id: 7, texts: [part] }])
    })

    it('gives up on a stuck worker after the timeout and stops it, so the next request gets a new one', async () => {
        const { SBO_QR } = getClasses()
        let terminated = false
        const stuckWorker = { postMessage() {}, terminate() { terminated = true } }
        const savedTimeout = SBO_QR.WORKER_TIMEOUT_MS
        SBO_QR.WORKER_TIMEOUT_MS = 30
        SBO_QR._worker = stuckWorker
        try {
            const pixels = { data: new Uint8ClampedArray(16), width: 2, height: 2 }
            await expect(SBO_QR.decodeInWorker(stuckWorker, pixels, false)).rejects.toThrow(/too long/)
            expect(terminated).toBe(true)
            expect(SBO_QR._worker).toBeNull()
            expect(SBO_QR._workerFailed).toBe(false)
            expect(SBO_QR._workerRequests.size).toBe(0)
        } finally {
            SBO_QR.WORKER_TIMEOUT_MS = savedTimeout
            SBO_QR._worker = null
        }
    })

    it('answers with an empty list when there is no code, and with an error for bad input', () => {
        const { ctx, posted } = loadWorker()
        ctx.onmessage({ data: { id: 1, data: new Uint8ClampedArray(100 * 100 * 4).fill(255), width: 100, height: 100 } })
        ctx.onmessage({ data: { id: 2, data: null, width: 100, height: 100 } })
        expect(posted[0]).toEqual({ id: 1, texts: [] })
        expect(posted[1].id).toBe(2)
        expect(typeof posted[1].error).toBe('string')
    })
})

// ---------------------------------------------------------------------------
// Reassembly
// ---------------------------------------------------------------------------

describe('SBO_QRAssembler', () => {
    it('reassembles parts scanned in any order, ignoring duplicates', async () => {
        const { SBO_QR, SBO_QRAssembler } = getClasses()
        const text = makeText(3000)
        const parts = await SBO_QR.split(text)
        const asm = new SBO_QRAssembler()

        expect(asm.add(parts[2])).toBe('added')
        expect(asm.add(parts[2])).toBe('duplicate')
        expect(asm.add(parts[0])).toBe('added')
        expect(asm.received).toBe(2)
        expect(asm.total).toBe(parts.length)
        for (let i = parts.length - 1; i >= 0; i--) asm.add(parts[i])

        expect(asm.isComplete()).toBe(true)
        expect(await asm.result()).toBe(text)
    })

    it('accepts a plain QR code without header as complete data', async () => {
        const { SBO_QRAssembler } = getClasses()
        const asm = new SBO_QRAssembler()
        expect(asm.add('{"keys":[1]}')).toBe('complete')
        expect(await asm.result()).toBe('{"keys":[1]}')
    })

    it('rejects a part from a different set', async () => {
        const { SBO_QR, SBO_QRAssembler } = getClasses()
        const a = await SBO_QR.split(makeText(2000))
        const b = await SBO_QR.split(makeText(2000) + 'x')
        const asm = new SBO_QRAssembler()
        asm.add(a[0])
        expect(() => asm.add(b[1])).toThrow(/different set/)
        expect(() => asm.add('plain text')).toThrow(/not part of the set/)
    })

    it('detects parts that do not fit together', async () => {
        const { SBO_QR, SBO_QRAssembler } = getClasses()
        const parts = await SBO_QR.split(makeText(2000))
        // Corrupt the data of one part but keep its header
        const tampered = parts[1].slice(0, -1) + (parts[1].endsWith('A') ? 'B' : 'A')
        const asm = new SBO_QRAssembler()
        asm.add(parts[0])
        asm.add(tampered)
        asm.add(parts[2])
        await expect(asm.result()).rejects.toThrow(/checksum/)
    })

    it('enforces limits on untrusted input', () => {
        const { SBO_QRAssembler } = getClasses()
        const asm = new SBO_QRAssembler()
        expect(() => asm.add('SBOQR1/0123abcd/1/99/x')).toThrow(/Too many parts/)
        expect(() => asm.add('SBOQR1/0123abcd/5/3/x')).toThrow(/Invalid part number/)
        expect(() => asm.add('SBOQR1/0123abcd/0/3/x')).toThrow(/Invalid part number/)
        expect(() => asm.add('SBOQR1/garbage')).toThrow(/header/)

        asm.add('SBOQR1/0123abcd/1/3/x')
        expect(() => asm.add('SBOQR1/0123abcd/2/4/x')).toThrow(/inconsistent/)
    })

    it('reports when parts are still missing', async () => {
        const { SBO_QR, SBO_QRAssembler } = getClasses()
        const parts = await SBO_QR.split(makeText(2000))
        const asm = new SBO_QRAssembler()
        asm.add(parts[0])
        expect(asm.isComplete()).toBe(false)
        await expect(asm.result()).rejects.toThrow(/Not all parts/)
    })
})

// ---------------------------------------------------------------------------
// Encode → image → decode round trip
// ---------------------------------------------------------------------------

describe('QR round trip', () => {
    it('a public key survives encode, render, decode and reassembly', async () => {
        const { SBO_QR, SBO_QRAssembler } = getClasses()
        const keyset = JSON.parse(readFileSync(join(fixturesDir, 'recipient-keyset.jwks.json'), 'utf-8'))
        const publicJwks = JSON.stringify(keyset.public)

        const parts = await SBO_QR.split(publicJwks)
        const asm = new SBO_QRAssembler()
        for (const part of parts) {
            const decoded = SBO_QR.decodeImageData(renderToImageData(SBO_QR.encode(part)), false)
            expect(decoded).toHaveLength(1)
            asm.add(decoded[0])
        }
        expect(await asm.result()).toBe(publicJwks)
    })

    it('a multi-part package survives the round trip in reverse order', async () => {
        const { SBO_QR, SBO_QRAssembler } = getClasses()
        const text = JSON.stringify({ type: 'sbo-encrypted', data: makeText(2500), name: 'Şeker 😀' })
        const parts = await SBO_QR.split(text)
        expect(parts.length).toBeGreaterThan(1)

        const asm = new SBO_QRAssembler()
        for (let i = parts.length - 1; i >= 0; i--) {
            const decoded = SBO_QR.decodeImageData(renderToImageData(SBO_QR.encode(parts[i])), true)
            asm.add(decoded[0])
        }
        // JSON comes back with non-ASCII characters escaped, which parses to the same value
        const result = await asm.result()
        expect(result).toMatch(/^[\x00-\x7f]*$/)
        expect(JSON.parse(result)).toEqual(JSON.parse(text))
    })

    it('finds nothing in an image without a QR code', () => {
        const { SBO_QR } = getClasses()
        const blank = { data: new Uint8ClampedArray(200 * 200 * 4).fill(255), width: 200, height: 200 }
        expect(SBO_QR.decodeImageData(blank, true)).toEqual([])
    })

    it('produces an SVG data URL containing only the drawing', () => {
        const { SBO_QR } = getClasses()
        const url = SBO_QR.toSvgDataUrl(SBO_QR.encode('SBOQR1/0123abcd/1/1/<script>alert(1)</script>'))
        expect(url.startsWith('data:image/svg+xml;charset=utf-8,')).toBe(true)
        const svg = decodeURIComponent(url.slice(url.indexOf(',') + 1))
        expect(svg).not.toContain('script')
        expect(svg).toMatch(/^<svg [^>]+><rect [^>]+\/><path d="[Mhvz0-9,\-]+" fill="#000"\/><\/svg>$/)
    })
})
