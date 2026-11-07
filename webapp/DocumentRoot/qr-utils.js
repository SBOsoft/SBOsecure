/*
Copyright (C) 2025, 2026 SBOSOFT, Serkan Özkan

This file is part of, SBOsecure, good enough security for ordinary people

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/*
 * QR code support: splitting data over several QR codes, putting it back together,
 * drawing codes and reading them from images or camera frames.
 *
 * Each code carries one part in this text format:
 *
 *     SBOQR1/<id>/<part>/<total>/<slice of the data>
 *
 *   id     first 8 hex digits of the SHA-256 of the full data. Groups the parts of one set
 *          and lets the reader check the reassembled data. It only detects mistakes (mixed
 *          sets, misreads); tampering is detected by AES-GCM and the package signature.
 *   part   1-based part number
 *   total  number of parts in the set
 *
 * A scanned code without the SBOQR1 header is accepted as complete data on its own,
 * e.g. a plain JSON QR code made with another tool.
 *
 * Depends on: SBO_CryptoUtils (crypto-utils.js), qrcodegen (vendor/qrcodegen/qrcodegen.js).
 * jsQR (vendor/jsqr/jsQR.js) is loaded on demand when the browser has no BarcodeDetector.
 */

class SBO_QR {
    static PREFIX = 'SBOQR1';
    /** Target size of the data slice in one code; keeps codes easy to scan from a screen */
    static CHUNK_BYTES = 800;
    /** Largest data offered as QR codes (about 13 codes) */
    static MAX_DISPLAY_BYTES = 10 * 1024;
    /** Limits applied to scanned input, which is untrusted */
    static MAX_PARTS = 20;
    static MAX_TOTAL_BYTES = 32 * 1024;
    /** Image files above this size are not opened at all */
    static MAX_IMAGE_FILE_BYTES = 40 * 1024 * 1024;
    static JSQR_URL = 'vendor/jsqr/jsQR.js';
    static WORKER_URL = 'qr-worker.js';
    /** A 1080p frame normally takes well under a second; anything this slow means the worker is stuck */
    static WORKER_TIMEOUT_MS = 10000;

    static PART_PATTERN = /^SBOQR1\/([0-9a-f]{8})\/(\d{1,3})\/(\d{1,3})\//;

    /**
     * UTF-8 size of a string in bytes.
     */
    static byteLength(text) {
        return new TextEncoder().encode(text).length;
    }

    /**
     * UTF-8 size of a single code point.
     */
    static codePointBytes(ch) {
        const cp = ch.codePointAt(0);
        if (cp < 0x80) return 1;
        if (cp < 0x800) return 2;
        if (cp < 0x10000) return 3;
        return 4;
    }

    /**
     * Returns text that contains only ASCII characters, when that can be done without changing meaning.
     *
     * Codes are stored as UTF-8 bytes, but QR readers disagree on how to decode non-ASCII bytes
     * (some assume Latin-1), which would corrupt names such as "Özkan". All data SBOsecure puts in
     * QR codes is JSON, and in valid JSON non-ASCII characters can only occur inside strings, where
     * they can be written as \uXXXX escapes. The escaped text parses to exactly the same values.
     * Text that is not valid JSON is returned unchanged.
     */
    static toAsciiSafe(text) {
        if (!/[^\x00-\x7f]/.test(text)) return text;
        try {
            JSON.parse(text);
        } catch {
            return text;
        }
        // Escapes UTF-16 code units, so characters outside the BMP become a valid surrogate pair escape
        return text.replace(/[^\x00-\x7f]/g, ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'));
    }

    /**
     * Size in bytes of the text as it will be stored in QR codes.
     */
    static encodedLength(text) {
        return SBO_QR.byteLength(SBO_QR.toAsciiSafe(text));
    }

    /**
     * True if the text is small enough to be shown as QR codes.
     */
    static canDisplay(text) {
        return !!text && SBO_QR.encodedLength(text) <= SBO_QR.MAX_DISPLAY_BYTES;
    }

    /**
     * Short identifier of a piece of data: first 8 hex digits of its SHA-256.
     */
    static async dataId(text) {
        const hash = await SBO_CryptoUtils.sha256(text);
        return SBO_CryptoUtils.hexEncode(new Uint8Array(hash)).slice(0, 8);
    }

    /**
     * Splits text into QR part strings of roughly equal size.
     * JSON is made ASCII-only first (see toAsciiSafe), so reassembly yields that escaped form.
     * Never splits a character, so every slice is valid UTF-8 on its own.
     * @param {string} input
     * @returns {Promise<string[]>}
     */
    static async split(input) {
        if (!input) throw new Error('Nothing to encode.');
        const text = SBO_QR.toAsciiSafe(input);
        const totalBytes = SBO_QR.byteLength(text);
        if (totalBytes > SBO_QR.MAX_DISPLAY_BYTES) {
            throw new Error('Data is too large for QR codes.');
        }
        // Equal-sized slices give codes of equal density
        const count = Math.ceil(totalBytes / SBO_QR.CHUNK_BYTES);
        const target = Math.ceil(totalBytes / count);

        const slices = [];
        let current = '';
        let currentBytes = 0;
        for (const ch of text) {
            const len = SBO_QR.codePointBytes(ch);
            if (currentBytes + len > target && current !== '') {
                slices.push(current);
                current = '';
                currentBytes = 0;
            }
            current += ch;
            currentBytes += len;
        }
        slices.push(current);

        const id = await SBO_QR.dataId(text);
        const parts = [];
        for (let i = 0; i < slices.length; i++) {
            parts.push(`${SBO_QR.PREFIX}/${id}/${i + 1}/${slices.length}/${slices[i]}`);
        }
        return parts;
    }

    /**
     * Parses one scanned part. Returns null if the text has no SBOQR1 header.
     * Throws if the header is present but invalid.
     * @returns {{id: string, index: number, total: number, data: string} | null}
     */
    static parsePart(text) {
        const m = SBO_QR.PART_PATTERN.exec(text);
        if (!m) {
            if (text.startsWith(SBO_QR.PREFIX + '/')) throw new Error('Unreadable SBOsecure QR code header.');
            return null;
        }
        const index = Number(m[2]);
        const total = Number(m[3]);
        if (total < 1 || index < 1 || index > total) {
            throw new Error('Invalid part number in QR code.');
        }
        return { id: m[1], index: index, total: total, data: text.slice(m[0].length) };
    }

    /**
     * Encodes one part string as a QR code (error correction level M).
     * @returns {qrcodegen.QrCode}
     */
    static encode(text) {
        return qrcodegen.QrCode.encodeText(text, qrcodegen.QrCode.Ecc.MEDIUM);
    }

    /**
     * Draws a QR code as an SVG data URL. Used in <img>, so no markup is ever injected into the page.
     * @param {qrcodegen.QrCode} qr
     * @param {number} border quiet zone in modules (the standard asks for 4)
     */
    static toSvgDataUrl(qr, border = 4) {
        const size = qr.size + border * 2;
        let path = '';
        for (let y = 0; y < qr.size; y++) {
            for (let x = 0; x < qr.size; x++) {
                if (qr.getModule(x, y)) {
                    path += `M${x + border},${y + border}h1v1h-1z`;
                }
            }
        }
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges">` +
            `<rect width="100%" height="100%" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
        return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
    }

    /**
     * Draws a QR code into a PNG blob, for saving codes as image files.
     * @param {qrcodegen.QrCode} qr
     * @param {number} scale pixels per module
     * @param {number} border quiet zone in modules
     * @returns {Promise<Blob>}
     */
    static toPngBlob(qr, scale = 8, border = 4) {
        const canvas = document.createElement('canvas');
        canvas.width = canvas.height = (qr.size + border * 2) * scale;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#fff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#000';
        for (let y = 0; y < qr.size; y++) {
            for (let x = 0; x < qr.size; x++) {
                if (qr.getModule(x, y)) {
                    ctx.fillRect((x + border) * scale, (y + border) * scale, scale, scale);
                }
            }
        }
        return new Promise((resolve, reject) => {
            canvas.toBlob(blob => (blob ? resolve(blob) : reject(new Error('Could not create image.'))), 'image/png');
        });
    }

    /* ---- Reading ------------------------------------------------------- */

    static _nativeDetector = undefined;   // undefined = not checked yet, null = not available
    static _jsQRPromise = null;
    static _worker = null;
    static _workerFailed = false;         // worker could not start; decode on the main thread instead
    static _workerUsers = 0;              // mounted scanners; the worker is stopped when none are left
    static _workerRequests = new Map();   // request id -> { resolve, reject }
    static _nextRequestId = 1;

    /**
     * Registers a user of the decoding worker (a mounted scanner).
     */
    static retainWorker() {
        SBO_QR._workerUsers++;
    }

    /**
     * Unregisters a user of the decoding worker and stops the worker when nobody needs it.
     */
    static releaseWorker() {
        SBO_QR._workerUsers = Math.max(0, SBO_QR._workerUsers - 1);
        if (SBO_QR._workerUsers === 0) {
            SBO_QR.stopWorker(new Error('The QR reader was closed.'));
        }
    }

    /**
     * Terminates the worker and rejects requests still waiting for it.
     */
    static stopWorker(reason) {
        if (SBO_QR._worker) {
            SBO_QR._worker.terminate();
            SBO_QR._worker = null;
        }
        for (const request of SBO_QR._workerRequests.values()) {
            request.reject(reason);
        }
        SBO_QR._workerRequests.clear();
    }

    /**
     * Returns the decoding worker, starting it on first use, or null if workers are unavailable.
     */
    static getWorker() {
        if (SBO_QR._worker || SBO_QR._workerFailed) return SBO_QR._worker;
        if (typeof Worker === 'undefined') {
            SBO_QR._workerFailed = true;
            return null;
        }
        try {
            const worker = new Worker(SBO_QR.WORKER_URL);
            worker.onmessage = (event) => {
                const msg = event.data;
                const request = SBO_QR._workerRequests.get(msg.id);
                if (!request) return;
                SBO_QR._workerRequests.delete(msg.id);
                if (msg.error) {
                    request.reject(new Error(msg.error));
                } else {
                    request.resolve(msg.texts);
                }
            };
            worker.onerror = (event) => {
                // Typically the worker or jsQR script failed to load: use the main thread from now on
                event.preventDefault();
                SBO_QR._workerFailed = true;
                SBO_QR.stopWorker(new Error('The QR reader worker failed.'));
            };
            SBO_QR._worker = worker;
        } catch {
            SBO_QR._workerFailed = true;
        }
        return SBO_QR._worker;
    }

    /**
     * Decodes pixels in the worker. The pixel buffer is transferred, so imageData is unusable afterwards.
     * If the worker does not answer within WORKER_TIMEOUT_MS it is assumed stuck: it is terminated
     * (the next request starts a fresh one) and the request fails with an error the caller can show.
     * The main thread is deliberately not used instead, as a decode that slow would freeze the page.
     * @returns {Promise<string[]>}
     */
    static decodeInWorker(worker, imageData, thorough) {
        return new Promise((resolve, reject) => {
            const id = SBO_QR._nextRequestId++;
            const timer = setTimeout(() => {
                if (!SBO_QR._workerRequests.has(id)) return;
                SBO_QR.stopWorker(new Error('Reading the QR code took too long. Trying again…'));
            }, SBO_QR.WORKER_TIMEOUT_MS);
            SBO_QR._workerRequests.set(id, {
                resolve: (texts) => { clearTimeout(timer); resolve(texts); },
                reject: (err) => { clearTimeout(timer); reject(err); }
            });
            worker.postMessage({
                id: id,
                data: imageData.data,
                width: imageData.width,
                height: imageData.height,
                thorough: thorough
            }, [imageData.data.buffer]);
        });
    }

    /**
     * Opens an image file as a bitmap, letting the browser scale it down while decoding when it
     * is larger than maxSize, so a huge photo does not have to be kept in memory at full size.
     * @param {File} file
     * @param {number} maxSize longest side of the returned bitmap, roughly
     * @returns {Promise<ImageBitmap>}
     */
    static async loadImageBitmap(file, maxSize) {
        if (file.size > SBO_QR.MAX_IMAGE_FILE_BYTES) {
            throw new Error(`${file.name} is too large (over ${SBO_QR.MAX_IMAGE_FILE_BYTES / (1024 * 1024)} MB).`);
        }
        const size = await SBO_QR.readImageSize(file);
        if (size && Math.max(size.width, size.height) > maxSize) {
            // Give only the longer side; the browser keeps the aspect ratio, even if EXIF rotation applies
            const options = size.width >= size.height
                ? { resizeWidth: maxSize, resizeQuality: 'high' }
                : { resizeHeight: maxSize, resizeQuality: 'high' };
            try {
                return await createImageBitmap(file, options);
            } catch {
                // Older browsers without resize options: decode at full size below
            }
        }
        return createImageBitmap(file);
    }

    /**
     * Reads the dimensions of an image file without keeping a decoded copy, or null if unknown.
     */
    static readImageSize(file) {
        return new Promise((resolve) => {
            const url = URL.createObjectURL(file);
            const img = new Image();
            img.onload = () => {
                URL.revokeObjectURL(url);
                resolve({ width: img.naturalWidth, height: img.naturalHeight });
            };
            img.onerror = () => {
                URL.revokeObjectURL(url);
                resolve(null);
            };
            img.src = url;
        });
    }

    /**
     * Returns a BarcodeDetector for QR codes if the browser has one, otherwise null.
     */
    static async getNativeDetector() {
        if (SBO_QR._nativeDetector !== undefined) return SBO_QR._nativeDetector;
        SBO_QR._nativeDetector = null;
        try {
            if (typeof BarcodeDetector !== 'undefined') {
                const formats = await BarcodeDetector.getSupportedFormats();
                if (formats.includes('qr_code')) {
                    SBO_QR._nativeDetector = new BarcodeDetector({ formats: ['qr_code'] });
                }
            }
        } catch {
            SBO_QR._nativeDetector = null;
        }
        return SBO_QR._nativeDetector;
    }

    /**
     * Loads the bundled jsQR library once, on first use.
     */
    static loadJsQR() {
        if (typeof jsQR === 'function') return Promise.resolve();
        if (!SBO_QR._jsQRPromise) {
            SBO_QR._jsQRPromise = new Promise((resolve, reject) => {
                const script = document.createElement('script');
                script.src = SBO_QR.JSQR_URL;
                script.onload = () => resolve();
                script.onerror = () => {
                    SBO_QR._jsQRPromise = null;
                    reject(new Error('Could not load the QR code reader.'));
                };
                document.head.appendChild(script);
            });
        }
        return SBO_QR._jsQRPromise;
    }

    /**
     * Decodes a QR code from raw RGBA pixels with jsQR. jsQR finds at most one code.
     * @param {{data: Uint8ClampedArray, width: number, height: number}} imageData
     * @param {boolean} thorough also look for light-on-dark codes (slower)
     * @returns {string[]}
     */
    static decodeImageData(imageData, thorough) {
        const result = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: thorough ? 'attemptBoth' : 'dontInvert'
        });
        return result && result.data ? [result.data] : [];
    }

    /**
     * Finds QR codes in an image, video frame or bitmap.
     * Uses the browser's BarcodeDetector when available (finds several codes per image),
     * otherwise jsQR on a scaled-down copy (one code per image), in a Web Worker when possible.
     * @param {CanvasImageSource} source
     * @param {number} width  natural width of the source
     * @param {number} height natural height of the source
     * @param {{maxSize?: number, thorough?: boolean}} options
     * @returns {Promise<string[]>} the text of each code found
     */
    static async decodeSource(source, width, height, options = {}) {
        const detector = await SBO_QR.getNativeDetector();
        if (detector) {
            try {
                const found = await detector.detect(source);
                const texts = [];
                for (const code of found) {
                    if (code.rawValue) texts.push(code.rawValue);
                }
                return texts;
            } catch {
                // Fall through to jsQR
            }
        }

        // Scale large images down: faster, and a huge image cannot freeze the page
        const maxSize = options.maxSize || 1600;
        const thorough = !!options.thorough;
        const scale = Math.min(1, maxSize / Math.max(width, height));
        const w = Math.max(1, Math.round(width * scale));
        const h = Math.max(1, Math.round(height * scale));
        const canvas = document.createElement('canvas');
        canvas.width = w;
        canvas.height = h;
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(source, 0, 0, w, h);

        const worker = SBO_QR.getWorker();
        if (worker) {
            try {
                return await SBO_QR.decodeInWorker(worker, ctx.getImageData(0, 0, w, h), thorough);
            } catch (err) {
                // Only fall back to the main thread if the worker itself is broken
                if (!SBO_QR._workerFailed) throw err;
            }
        }
        await SBO_QR.loadJsQR();
        return SBO_QR.decodeImageData(ctx.getImageData(0, 0, w, h), thorough);
    }
}

/**
 * Collects scanned QR parts, in any order, until a set is complete.
 * Scanned text is untrusted: part counts and total size are limited, and the
 * reassembled data must match the id in the part headers.
 */
class SBO_QRAssembler {
    constructor() {
        this.reset();
    }

    reset() {
        this.id = null;
        this.total = 0;
        this.parts = new Map();
        this.bytes = 0;
        this.plainText = null;
    }

    /** Number of distinct parts received so far */
    get received() {
        return this.plainText !== null ? 1 : this.parts.size;
    }

    isComplete() {
        return this.plainText !== null || (this.total > 0 && this.parts.size === this.total);
    }

    /**
     * Adds one scanned code.
     * @param {string} text
     * @returns {'added' | 'duplicate' | 'complete'}
     * @throws {Error} with a message for the user if the code does not fit the current set
     */
    add(text) {
        if (this.isComplete()) return 'complete';

        const part = SBO_QR.parsePart(text);
        if (!part) {
            if (this.parts.size > 0) {
                throw new Error('This QR code is not part of the set being scanned. Scan the remaining parts or start over.');
            }
            if (SBO_QR.byteLength(text) > SBO_QR.MAX_TOTAL_BYTES) throw new Error('Scanned data is too large.');
            this.plainText = text;
            return 'complete';
        }

        if (part.total > SBO_QR.MAX_PARTS) {
            throw new Error(`Too many parts (${part.total}); at most ${SBO_QR.MAX_PARTS} are supported.`);
        }
        if (this.id === null) {
            this.id = part.id;
            this.total = part.total;
        } else if (part.id !== this.id) {
            throw new Error('This QR code belongs to a different set. Scan the remaining parts or start over.');
        } else if (part.total !== this.total) {
            throw new Error('This QR code has an inconsistent part count. Start over.');
        }

        if (this.parts.has(part.index)) return 'duplicate';

        const len = SBO_QR.byteLength(part.data);
        if (this.bytes + len > SBO_QR.MAX_TOTAL_BYTES) throw new Error('Scanned data is too large.');
        this.parts.set(part.index, part.data);
        this.bytes += len;
        return this.isComplete() ? 'complete' : 'added';
    }

    /**
     * Returns the reassembled data once complete.
     * @throws {Error} if parts are missing or the data does not match its id
     */
    async result() {
        if (!this.isComplete()) throw new Error('Not all parts have been scanned yet.');
        if (this.plainText !== null) return this.plainText;

        let text = '';
        for (let i = 1; i <= this.total; i++) {
            text += this.parts.get(i);
        }
        const id = await SBO_QR.dataId(text);
        if (id !== this.id) {
            throw new Error('The scanned parts do not fit together (checksum mismatch). Start over.');
        }
        return text;
    }
}

// Expose classes on globalThis, as crypto-utils.js does, so tests running in a VM can reach them
globalThis.SBO_QR          = SBO_QR;
globalThis.SBO_QRAssembler = SBO_QRAssembler;
