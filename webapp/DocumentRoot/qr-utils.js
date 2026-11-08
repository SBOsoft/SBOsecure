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

    /*
     * Compact format: SBOQR2/<ID>/<part>/<total>/<Base45 of a slice of SBO_QRCompact bytes>
     * The whole code uses only QR alphanumeric characters (stored at 5.5 bits each). ID is the
     * first 8 hex digits (upper case) of the SHA-256 of the complete compact bytes.
     */
    static COMPACT_PREFIX = 'SBOQR2';
    static COMPACT_PART_PATTERN = /^SBOQR2\/([0-9A-F]{8})\/(\d{1,3})\/(\d{1,3})\//;
    /** Bytes per compact code: gives at most a version 23 code, the same density as JSON codes */
    static COMPACT_CHUNK_BYTES = 816;
    /** QR alphanumeric character set; Base45 uses exactly these characters */
    static ALPHANUMERIC_PATTERN = /^[0-9A-Z $%*+\-./:]*$/;
    /** More codes than this are not offered for display */
    static MAX_DISPLAY_PARTS = 13;
    /** Longest name put in a public key code; longer names are cut, so they cannot inflate the codes */
    static MAX_NAME_CHARS = 100;

    /**
     * Cuts a name to MAX_NAME_CHARS characters, counting whole characters (code points), so an
     * emoji or other character outside the BMP is never split in half.
     * @returns {string|undefined} undefined for an empty or missing name
     */
    static limitName(name) {
        if (typeof name !== 'string' || name.length === 0) return undefined;
        const chars = Array.from(name);
        return chars.length > SBO_QR.MAX_NAME_CHARS ? chars.slice(0, SBO_QR.MAX_NAME_CHARS).join('') : name;
    }

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
     * Parses one scanned part. Returns null if the text has no SBOsecure header.
     * Throws if the header is present but invalid, or from an unknown (newer) format.
     * @returns {{format: 'json'|'compact', id: string, index: number, total: number, data: string} | null}
     */
    static parsePart(text) {
        let format;
        let m;
        if (text.startsWith(SBO_QR.PREFIX + '/')) {
            format = 'json';
            m = SBO_QR.PART_PATTERN.exec(text);
        } else if (text.startsWith(SBO_QR.COMPACT_PREFIX + '/')) {
            format = 'compact';
            m = SBO_QR.COMPACT_PART_PATTERN.exec(text);
        } else if (/^SBOQR\d+\//.test(text)) {
            throw new Error('This QR code was made by a newer version of SBOsecure.');
        } else {
            return null;
        }
        if (!m) throw new Error('Unreadable SBOsecure QR code header.');
        const index = Number(m[2]);
        const total = Number(m[3]);
        if (total < 1 || index < 1 || index > total) {
            throw new Error('Invalid part number in QR code.');
        }
        const data = text.slice(m[0].length);
        if (format === 'compact' && !SBO_QR.ALPHANUMERIC_PATTERN.test(data)) {
            throw new Error('Damaged QR data (invalid character).');
        }
        return { format: format, id: m[1], index: index, total: total, data: data };
    }

    /**
     * Identifier of compact data: first 8 hex digits (upper case) of its SHA-256.
     */
    static async compactId(bytes) {
        const hash = await crypto.subtle.digest('SHA-256', bytes);
        return SBO_CryptoUtils.hexEncode(new Uint8Array(hash)).slice(0, 8).toUpperCase();
    }

    /**
     * Splits compact bytes into SBOQR2 part strings of roughly equal size.
     * Every slice except the last has an even number of bytes, so each part's Base45 text ends on a
     * complete 3-character group. Such a group never ends in a space (its last character is at most
     * 'W'), and the final 2-character group ends in a digit, so a reader that trims trailing spaces
     * can never cut off data.
     * @param {Uint8Array} bytes
     * @returns {Promise<string[]>}
     */
    static async splitCompact(bytes) {
        const count = Math.max(1, Math.ceil(bytes.length / SBO_QR.COMPACT_CHUNK_BYTES));
        let size = Math.ceil(bytes.length / count);
        if (size % 2 === 1) size++;
        const slices = [];
        for (let offset = 0; offset < bytes.length; offset += size) {
            slices.push(bytes.slice(offset, offset + size));
        }
        const id = await SBO_QR.compactId(bytes);
        const parts = [];
        for (let i = 0; i < slices.length; i++) {
            parts.push(`${SBO_QR.COMPACT_PREFIX}/${id}/${i + 1}/${slices.length}/${SBO_Base45.encode(slices[i])}`);
        }
        return parts;
    }

    /**
     * Decodes parts again exactly as a receiver would (in reverse order, to also exercise
     * any-order assembly) and returns the reassembled text, or null if that fails.
     */
    static async readBack(parts) {
        try {
            const asm = new SBO_QRAssembler();
            for (let i = parts.length - 1; i >= 0; i--) asm.add(parts[i]);
            return await asm.result();
        } catch {
            return null;
        }
    }

    /**
     * Prepares data for display as QR codes.
     * Uses the compact format (SBOQR2) when the data can be represented exactly, otherwise the JSON
     * format (SBOQR1). Either way the codes are decoded again before they are returned and must
     * reproduce the data, so codes that would not read back correctly are never shown.
     * @param {string} text the data (JSON)
     * @param {{name?: string, includeSignerKey?: boolean}} options see SBO_QRCompact.encode
     * @returns {Promise<{parts: string[], compact: boolean, signerKeyLeftOut: boolean, signerKeyOptional: boolean}>}
     * @throws {Error} with a message for the user if the data is too large or cannot be encoded
     */
    static async encodeForDisplay(text, options = {}) {
        if (!text) throw new Error('There is nothing to show.');
        // Cap the name once, so encoding and the read-back check below use the same value
        options = Object.assign({}, options, { name: SBO_QR.limitName(options.name) });
        const tooLarge = () => new Error(`This data needs more than ${SBO_QR.MAX_DISPLAY_PARTS} QR codes. Use Download instead.`);

        const compact = await SBO_QRCompact.encode(text, options);
        if (compact) {
            const parts = await SBO_QR.splitCompact(compact.bytes);
            let ok = true;
            for (const part of parts) {
                if (!SBO_QR.ALPHANUMERIC_PATTERN.test(part)) ok = false;
            }
            const decoded = ok ? await SBO_QR.readBack(parts) : null;
            if (decoded !== null && await SBO_QRCompact.matchesOriginal(text, decoded, options)) {
                if (parts.length > SBO_QR.MAX_DISPLAY_PARTS) throw tooLarge();
                return {
                    parts: parts,
                    compact: true,
                    signerKeyLeftOut: compact.signerKeyLeftOut,
                    signerKeyOptional: compact.signerKeyOptional
                };
            }
            console.warn('Compact QR encoding did not read back exactly; using the JSON format.');
        }

        if (!SBO_QR.canDisplay(text)) throw tooLarge();
        const parts = await SBO_QR.split(text);
        const decoded = await SBO_QR.readBack(parts);
        if (decoded !== SBO_QR.toAsciiSafe(text)) throw new Error('This data cannot be shown as QR codes.');
        if (parts.length > SBO_QR.MAX_DISPLAY_PARTS) throw tooLarge();
        return { parts: parts, compact: false, signerKeyLeftOut: false, signerKeyOptional: false };
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
 * Base45 (RFC 9285): 2 bytes become 3 characters, all from the QR alphanumeric character set.
 * Such text is stored in alphanumeric mode (5.5 bits per character, about 97% efficient) and
 * every QR reader returns it as plain text, unlike raw binary.
 */
class SBO_Base45 {
    static ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

    /**
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    static encode(bytes) {
        const A = SBO_Base45.ALPHABET;
        let out = '';
        let i = 0;
        for (; i + 1 < bytes.length; i += 2) {
            const n = bytes[i] * 256 + bytes[i + 1];
            const c = n % 45;
            const d = Math.floor(n / 45) % 45;
            const e = Math.floor(n / 2025);
            out += A[c] + A[d] + A[e];
        }
        if (i < bytes.length) {
            const n = bytes[i];
            out += A[n % 45] + A[Math.floor(n / 45)];
        }
        return out;
    }

    /**
     * @param {string} text
     * @returns {Uint8Array}
     * @throws {Error} for characters outside the alphabet or impossible values
     */
    static decode(text) {
        if (text.length % 3 === 1) throw new Error('Damaged QR data (invalid length).');
        const out = new Uint8Array(Math.floor(text.length / 3) * 2 + (text.length % 3 === 2 ? 1 : 0));
        let o = 0;
        for (let i = 0; i < text.length; i += 3) {
            const c = SBO_Base45.valueAt(text, i);
            const d = SBO_Base45.valueAt(text, i + 1);
            if (i + 2 < text.length) {
                const n = c + d * 45 + SBO_Base45.valueAt(text, i + 2) * 2025;
                if (n > 0xffff) throw new Error('Damaged QR data (invalid value).');
                out[o++] = n >> 8;
                out[o++] = n & 0xff;
            } else {
                const n = c + d * 45;
                if (n > 0xff) throw new Error('Damaged QR data (invalid value).');
                out[o++] = n;
            }
        }
        return out;
    }

    static valueAt(text, i) {
        const v = SBO_Base45.ALPHABET.indexOf(text[i]);
        if (v < 0) throw new Error('Damaged QR data (invalid character).');
        return v;
    }
}

/**
 * Writes the compact binary layout. Lengths are unsigned LEB128 varints.
 */
class SBO_ByteWriter {
    constructor() {
        this.bytes = [];
    }
    u8(v) {
        this.bytes.push(v & 0xff);
    }
    varint(v) {
        if (!Number.isInteger(v) || v < 0 || v > 0x0fffffff) throw new Error('Value out of range.');
        do {
            let b = v & 0x7f;
            v = Math.floor(v / 128);
            if (v > 0) b |= 0x80;
            this.bytes.push(b);
        } while (v > 0);
    }
    raw(bytes) {
        for (const b of bytes) this.bytes.push(b);
    }
    blob(bytes) {
        this.varint(bytes.length);
        this.raw(bytes);
    }
    str(text) {
        this.blob(new TextEncoder().encode(text));
    }
    toBytes() {
        return new Uint8Array(this.bytes);
    }
}

/**
 * Reads the compact binary layout. Scanned data is untrusted: every read is bounds-checked and
 * strings must be valid UTF-8.
 */
class SBO_ByteReader {
    constructor(bytes) {
        this.bytes = bytes;
        this.pos = 0;
    }
    need(n) {
        if (this.pos + n > this.bytes.length) throw new Error('Damaged QR data (too short).');
    }
    u8() {
        this.need(1);
        return this.bytes[this.pos++];
    }
    varint() {
        let v = 0;
        let factor = 1;
        for (let i = 0; i < 4; i++) {
            const b = this.u8();
            v += (b & 0x7f) * factor;
            if (!(b & 0x80)) return v;
            factor *= 128;
        }
        throw new Error('Damaged QR data (invalid length).');
    }
    raw(n) {
        this.need(n);
        const out = this.bytes.slice(this.pos, this.pos + n);
        this.pos += n;
        return out;
    }
    blob() {
        return this.raw(this.varint());
    }
    str() {
        try {
            return new TextDecoder('utf-8', { fatal: true }).decode(this.blob());
        } catch (err) {
            if (err.message.startsWith('Damaged')) throw err;
            throw new Error('Damaged QR data (invalid text).');
        }
    }
    end() {
        if (this.pos !== this.bytes.length) throw new Error('Damaged QR data (unexpected extra data).');
    }
}

/**
 * Lossless compact binary form of the JSON that SBOsecure shows as QR codes: public keys,
 * encrypted packages and password-encrypted packages. Base64 becomes raw bytes, field names
 * disappear, and values that are always the same (RSA exponent, algorithms) are left out.
 *
 * decode(encode(json)) rebuilds the original JSON, with the same field order, so the package
 * signature (computed over JSON.stringify of the parsed package) still verifies. encode() refuses
 * (returns null) anything it cannot represent exactly, and SBO_QR.encodeForDisplay() additionally
 * decodes every result again before showing it; such data is shown in the JSON format instead.
 *
 * Optionally, a signed package can leave out the signer's public key and carry only the first
 * 8 bytes of its fingerprint (signerKeyRef); the receiver then verifies with the matching key
 * from their contacts.
 *
 * Layout (all types): type u8, layout version u8, flags u8, then type-specific fields.
 * The tables below are part of the format: never reorder them, only append.
 */
class SBO_QRCompact {
    static TYPE_PUBLIC_KEY = 1;
    static TYPE_PACKAGE = 2;
    static TYPE_PASSWORD_PACKAGE = 3;
    static LAYOUT_VERSION = 1;
    static SIGNER_REF_BYTES = 8;
    static MAX_RECIPIENTS = 100;
    static MAX_KEYS = 8;

    /** Content types stored as a 1-byte code (code = index + 1; 0 = stored as text) */
    static CONTENT_TYPES = ['text/plain', 'application/octet-stream'];

    /** The two kinds of RSA public key the app creates, as exported by Web Crypto (in export order) */
    static KEY_KINDS = {
        1: { key_ops: ['verify'], alg: 'RS256' },
        2: { key_ops: ['encrypt'], alg: 'RSA-OAEP-256' }
    };

    /* ---- Helpers ------------------------------------------------------ */

    /** Thrown internally when data cannot be represented exactly; encode() then returns null */
    static notCompactable(reason) {
        const err = new Error('Not compactable: ' + reason);
        err.notCompactable = true;
        return err;
    }

    static keysOf(obj) {
        return (obj && typeof obj === 'object' && !Array.isArray(obj)) ? Object.keys(obj) : null;
    }

    static sameList(a, b) {
        if (!a || a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }

    /** Standard padded base64 to bytes, only if re-encoding gives back exactly the same text */
    static base64ToBytes(text) {
        if (typeof text !== 'string' || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
            throw SBO_QRCompact.notCompactable('invalid base64');
        }
        const b64 = new SBO_Base64(false);
        const bytes = b64.decodeAsByteArray(text);
        if (b64.encodeBytes(bytes) !== text) throw SBO_QRCompact.notCompactable('non-canonical base64');
        return bytes;
    }

    static bytesToBase64(bytes) {
        return new SBO_Base64(false).encodeBytes(bytes);
    }

    /** Unpadded base64url (as used in JWKs) to bytes, only if re-encoding gives back the same text */
    static base64UrlToBytes(text) {
        if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
            throw SBO_QRCompact.notCompactable('invalid base64url');
        }
        const padded = text + '='.repeat((4 - (text.length % 4)) % 4);
        const bytes = new SBO_Base64(true).decodeAsByteArray(padded);
        if (SBO_QRCompact.bytesToBase64Url(bytes) !== text) throw SBO_QRCompact.notCompactable('non-canonical base64url');
        return bytes;
    }

    static bytesToBase64Url(bytes) {
        return new SBO_Base64(true).encodeBytes(bytes).replace(/=+$/, '');
    }

    static hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        return bytes;
    }

    /** Sorted-key JSON, to compare data where member order does not matter (public keys) */
    static canonicalJson(value) {
        if (Array.isArray(value)) {
            const items = [];
            for (const v of value) items.push(SBO_QRCompact.canonicalJson(v));
            return '[' + items.join(',') + ']';
        }
        if (value && typeof value === 'object') {
            const members = [];
            for (const k of Object.keys(value).sort()) {
                members.push(JSON.stringify(k) + ':' + SBO_QRCompact.canonicalJson(value[k]));
            }
            return '{' + members.join(',') + '}';
        }
        return JSON.stringify(value);
    }

    /**
     * Writes an RSA public JWK of the given kind as its modulus only.
     * Refuses keys with any member that is not exactly what the app exports.
     */
    static writeRsaKey(w, jwk, kind) {
        const spec = SBO_QRCompact.KEY_KINDS[kind];
        const keys = SBO_QRCompact.keysOf(jwk);
        if (!keys || keys.length !== 6 || jwk.kty !== 'RSA' || jwk.e !== 'AQAB' || jwk.ext !== true ||
            jwk.alg !== spec.alg || !SBO_QRCompact.sameList(jwk.key_ops, spec.key_ops)) {
            throw SBO_QRCompact.notCompactable('unexpected key format');
        }
        w.blob(SBO_QRCompact.base64UrlToBytes(jwk.n));
    }

    static readRsaKey(r, kind) {
        const spec = SBO_QRCompact.KEY_KINDS[kind];
        const n = r.blob();
        if (n.length < 128 || n.length > 1024) throw new Error('Damaged QR data (invalid key).');
        return {
            key_ops: spec.key_ops.slice(),
            ext: true,
            alg: spec.alg,
            kty: 'RSA',
            n: SBO_QRCompact.bytesToBase64Url(n),
            e: 'AQAB'
        };
    }

    static kindOfKey(jwk) {
        for (const kind of Object.keys(SBO_QRCompact.KEY_KINDS)) {
            if (jwk && SBO_QRCompact.sameList(jwk.key_ops, SBO_QRCompact.KEY_KINDS[kind].key_ops)) return Number(kind);
        }
        throw SBO_QRCompact.notCompactable('unknown key type');
    }

    /* ---- Encoding ----------------------------------------------------- */

    /**
     * Encodes JSON text compactly.
     * @param {string} text
     * @param {{name?: string, includeSignerKey?: boolean}} options
     *        name: key name to put in a public key code; includeSignerKey: keep the signer's
     *        public key in a signed package instead of a fingerprint reference
     * @returns {Promise<{bytes: Uint8Array, signerKeyLeftOut: boolean, signerKeyOptional: boolean} | null>}
     *          null if the data cannot be represented exactly
     */
    static async encode(text, options = {}) {
        let obj;
        try {
            obj = JSON.parse(text);
        } catch {
            return null;
        }
        try {
            const w = new SBO_ByteWriter();
            const keys = SBO_QRCompact.keysOf(obj);
            if (SBO_QRCompact.sameList(keys, ['keys'])) {
                SBO_QRCompact.encodePublicKey(w, obj, options.name);
                return { bytes: w.toBytes(), signerKeyLeftOut: false, signerKeyOptional: false };
            }
            if (obj && obj.type === 'sbo-encrypted') {
                const signed = !!obj.signature;
                const leaveOut = signed && !options.includeSignerKey;
                await SBO_QRCompact.encodePackage(w, obj, leaveOut);
                return { bytes: w.toBytes(), signerKeyLeftOut: leaveOut, signerKeyOptional: signed };
            }
            if (obj && obj.type === 'sbo-pbkdf-encrypted') {
                SBO_QRCompact.encodePasswordPackage(w, obj);
                return { bytes: w.toBytes(), signerKeyLeftOut: false, signerKeyOptional: false };
            }
            return null;
        } catch (err) {
            if (err.notCompactable) return null;
            throw err;
        }
    }

    static encodePublicKey(w, jwks, name) {
        if (!Array.isArray(jwks.keys) || jwks.keys.length === 0 || jwks.keys.length > SBO_QRCompact.MAX_KEYS) {
            throw SBO_QRCompact.notCompactable('unexpected key list');
        }
        const hasName = typeof name === 'string' && name.length > 0;
        w.u8(SBO_QRCompact.TYPE_PUBLIC_KEY);
        w.u8(SBO_QRCompact.LAYOUT_VERSION);
        w.u8(hasName ? 1 : 0);
        if (hasName) w.str(name);
        w.varint(jwks.keys.length);
        for (const jwk of jwks.keys) {
            const kind = SBO_QRCompact.kindOfKey(jwk);
            w.u8(kind);
            SBO_QRCompact.writeRsaKey(w, jwk, kind);
        }
    }

    static async encodePackage(w, p, leaveOutSignerKey) {
        if (!SBO_QRCompact.sameList(SBO_QRCompact.keysOf(p),
            ['version', 'type', 'encryptedContent', 'encryptedKeys', 'signature', 'signerPublicKey']) || p.version !== 1) {
            throw SBO_QRCompact.notCompactable('unexpected package fields');
        }
        const ec = p.encryptedContent;
        const ecKeys = SBO_QRCompact.keysOf(ec);
        const hasName = !!ecKeys && ecKeys.includes('originalName');
        const hasType = !!ecKeys && ecKeys.includes('contentType');
        const expectedEcKeys = ['ciphertext', 'iv'];
        if (hasName) expectedEcKeys.push('originalName');
        if (hasType) expectedEcKeys.push('contentType');
        if (!SBO_QRCompact.sameList(ecKeys, expectedEcKeys) ||
            (hasName && typeof ec.originalName !== 'string') || (hasType && typeof ec.contentType !== 'string')) {
            throw SBO_QRCompact.notCompactable('unexpected content fields');
        }

        const entries = p.encryptedKeys;
        if (!Array.isArray(entries) || entries.length === 0 || entries.length > SBO_QRCompact.MAX_RECIPIENTS) {
            throw SBO_QRCompact.notCompactable('unexpected recipients');
        }
        // All recipient entries must have the same shape: with keyId (current) or without (older versions)
        const hasKeyIds = SBO_QRCompact.sameList(SBO_QRCompact.keysOf(entries[0]), ['recipientName', 'keyId', 'encryptedKey']);
        const entryKeys = hasKeyIds ? ['recipientName', 'keyId', 'encryptedKey'] : ['recipientName', 'encryptedKey'];
        for (const entry of entries) {
            if (!SBO_QRCompact.sameList(SBO_QRCompact.keysOf(entry), entryKeys) || typeof entry.recipientName !== 'string' ||
                (hasKeyIds && !/^[0-9a-f]{64}$/.test(entry.keyId))) {
                throw SBO_QRCompact.notCompactable('unexpected recipient entry');
            }
        }

        const signed = p.signature !== null || p.signerPublicKey !== null;
        if (signed && (typeof p.signature !== 'string' || !p.signerPublicKey)) {
            throw SBO_QRCompact.notCompactable('incomplete signature');
        }
        const byRef = signed && leaveOutSignerKey;

        const flags = (hasName ? 1 : 0) | (hasType ? 2 : 0) | (hasKeyIds ? 4 : 0) | (signed ? 8 : 0) | (byRef ? 16 : 0);
        w.u8(SBO_QRCompact.TYPE_PACKAGE);
        w.u8(SBO_QRCompact.LAYOUT_VERSION);
        w.u8(flags);
        w.blob(SBO_QRCompact.base64ToBytes(ec.ciphertext));
        w.blob(SBO_QRCompact.base64ToBytes(ec.iv));
        if (hasName) w.str(ec.originalName);
        if (hasType) {
            const code = SBO_QRCompact.CONTENT_TYPES.indexOf(ec.contentType);
            w.u8(code + 1);
            if (code < 0) w.str(ec.contentType);
        }
        w.varint(entries.length);
        for (const entry of entries) {
            w.str(entry.recipientName);
            if (hasKeyIds) w.raw(SBO_QRCompact.hexToBytes(entry.keyId));
            w.blob(SBO_QRCompact.base64ToBytes(entry.encryptedKey));
        }
        if (signed) {
            w.blob(SBO_QRCompact.base64ToBytes(p.signature));
            if (byRef) {
                let thumb;
                try {
                    thumb = await SBO_CryptoUtils.jwkThumbprint(p.signerPublicKey);
                } catch {
                    throw SBO_QRCompact.notCompactable('malformed signer key');
                }
                w.raw(SBO_QRCompact.hexToBytes(thumb.slice(0, SBO_QRCompact.SIGNER_REF_BYTES * 2)));
            } else {
                SBO_QRCompact.writeRsaKey(w, p.signerPublicKey, 1);
            }
        }
    }

    static encodePasswordPackage(w, p) {
        if (!SBO_QRCompact.sameList(SBO_QRCompact.keysOf(p), ['version', 'type', 'encryptedContent', 'pbkdf']) || p.version !== 1 ||
            !SBO_QRCompact.sameList(SBO_QRCompact.keysOf(p.encryptedContent), ['ciphertext', 'iv']) ||
            !SBO_QRCompact.sameList(SBO_QRCompact.keysOf(p.pbkdf), ['salt'])) {
            throw SBO_QRCompact.notCompactable('unexpected password package fields');
        }
        w.u8(SBO_QRCompact.TYPE_PASSWORD_PACKAGE);
        w.u8(SBO_QRCompact.LAYOUT_VERSION);
        w.u8(0);
        w.blob(SBO_QRCompact.base64ToBytes(p.encryptedContent.ciphertext));
        w.blob(SBO_QRCompact.base64ToBytes(p.encryptedContent.iv));
        w.blob(SBO_QRCompact.base64ToBytes(p.pbkdf.salt));
    }

    /* ---- Decoding ----------------------------------------------------- */

    /**
     * Rebuilds the JSON text from compact bytes.
     *  - public key: the public.jwks.json text, or {"name":…,"jwks":"…"} when a name was included
     *  - package: the package JSON; with a left-out signer key, signerPublicKey is null and
     *    signerKeyRef holds the fingerprint prefix (16 hex digits)
     *  - password package: the package JSON
     * @param {Uint8Array} bytes
     * @returns {string}
     * @throws {Error} for damaged or unsupported data
     */
    static decode(bytes) {
        const r = new SBO_ByteReader(bytes);
        const type = r.u8();
        const layout = r.u8();
        if (layout !== SBO_QRCompact.LAYOUT_VERSION) {
            throw new Error('This QR code was made by a newer version of SBOsecure.');
        }
        let text;
        if (type === SBO_QRCompact.TYPE_PUBLIC_KEY) {
            text = SBO_QRCompact.decodePublicKey(r);
        } else if (type === SBO_QRCompact.TYPE_PACKAGE) {
            text = SBO_QRCompact.decodePackage(r);
        } else if (type === SBO_QRCompact.TYPE_PASSWORD_PACKAGE) {
            text = SBO_QRCompact.decodePasswordPackage(r);
        } else {
            throw new Error('This QR code was made by a newer version of SBOsecure.');
        }
        r.end();
        return text;
    }

    static decodePublicKey(r) {
        const flags = r.u8();
        if (flags & ~1) throw new Error('This QR code was made by a newer version of SBOsecure.');
        const name = (flags & 1) ? r.str() : null;
        const count = r.varint();
        if (count === 0 || count > SBO_QRCompact.MAX_KEYS) throw new Error('Damaged QR data (invalid key count).');
        const keys = [];
        for (let i = 0; i < count; i++) {
            const kind = r.u8();
            if (!SBO_QRCompact.KEY_KINDS[kind]) throw new Error('Damaged QR data (unknown key type).');
            keys.push(SBO_QRCompact.readRsaKey(r, kind));
        }
        const jwksText = JSON.stringify({ keys: keys });
        return name !== null ? JSON.stringify({ name: name, jwks: jwksText }) : jwksText;
    }

    static decodePackage(r) {
        const flags = r.u8();
        if (flags & ~31) throw new Error('This QR code was made by a newer version of SBOsecure.');
        const hasName = !!(flags & 1), hasType = !!(flags & 2), hasKeyIds = !!(flags & 4);
        const signed = !!(flags & 8), byRef = !!(flags & 16);
        if (byRef && !signed) throw new Error('Damaged QR data (invalid flags).');

        const ec = {
            ciphertext: SBO_QRCompact.bytesToBase64(r.blob()),
            iv: SBO_QRCompact.bytesToBase64(r.blob())
        };
        if (hasName) ec.originalName = r.str();
        if (hasType) {
            const code = r.u8();
            if (code === 0) {
                ec.contentType = r.str();
            } else if (code <= SBO_QRCompact.CONTENT_TYPES.length) {
                ec.contentType = SBO_QRCompact.CONTENT_TYPES[code - 1];
            } else {
                throw new Error('This QR code was made by a newer version of SBOsecure.');
            }
        }
        const count = r.varint();
        if (count === 0 || count > SBO_QRCompact.MAX_RECIPIENTS) throw new Error('Damaged QR data (invalid recipient count).');
        const entries = [];
        for (let i = 0; i < count; i++) {
            const entry = { recipientName: r.str() };
            if (hasKeyIds) entry.keyId = SBO_CryptoUtils.hexEncode(r.raw(32));
            entry.encryptedKey = SBO_QRCompact.bytesToBase64(r.blob());
            entries.push(entry);
        }
        const pkg = {
            version: 1,
            type: 'sbo-encrypted',
            encryptedContent: ec,
            encryptedKeys: entries,
            signature: null,
            signerPublicKey: null
        };
        if (signed) {
            pkg.signature = SBO_QRCompact.bytesToBase64(r.blob());
            if (byRef) {
                pkg.signerKeyRef = SBO_CryptoUtils.hexEncode(r.raw(SBO_QRCompact.SIGNER_REF_BYTES));
            } else {
                pkg.signerPublicKey = SBO_QRCompact.readRsaKey(r, 1);
            }
        }
        return JSON.stringify(pkg);
    }

    static decodePasswordPackage(r) {
        const flags = r.u8();
        if (flags !== 0) throw new Error('This QR code was made by a newer version of SBOsecure.');
        return JSON.stringify({
            version: 1,
            type: 'sbo-pbkdf-encrypted',
            encryptedContent: {
                ciphertext: SBO_QRCompact.bytesToBase64(r.blob()),
                iv: SBO_QRCompact.bytesToBase64(r.blob())
            },
            pbkdf: { salt: SBO_QRCompact.bytesToBase64(r.blob()) }
        });
    }

    /**
     * True if decoded compact data represents exactly the original JSON, given the options it
     * was encoded with. Packages must match character for character, so signatures still verify.
     */
    static async matchesOriginal(originalText, decodedText, options = {}) {
        let original, decoded;
        try {
            original = JSON.parse(originalText);
            decoded = JSON.parse(decodedText);
        } catch {
            return false;
        }
        if (SBO_QRCompact.sameList(SBO_QRCompact.keysOf(original), ['keys'])) {
            let jwks = decoded;
            const hasName = typeof options.name === 'string' && options.name.length > 0;
            if (hasName) {
                if (!decoded || decoded.name !== options.name || typeof decoded.jwks !== 'string') return false;
                jwks = JSON.parse(decoded.jwks);
            }
            return SBO_QRCompact.canonicalJson(jwks) === SBO_QRCompact.canonicalJson(original);
        }
        if (original && original.type === 'sbo-encrypted' && original.signature && !options.includeSignerKey) {
            const ref = (await SBO_CryptoUtils.jwkThumbprint(original.signerPublicKey)).slice(0, SBO_QRCompact.SIGNER_REF_BYTES * 2);
            const expected = Object.assign({}, original, { signerPublicKey: null, signerKeyRef: ref });
            return JSON.stringify(decoded) === JSON.stringify(expected);
        }
        return JSON.stringify(decoded) === JSON.stringify(original);
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
        this.format = null;     // 'json' (SBOQR1) or 'compact' (SBOQR2)
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
            this.format = part.format;
            this.total = part.total;
        } else if (part.id !== this.id || part.format !== this.format) {
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
     * Returns the reassembled data once complete. Compact (SBOQR2) data is decoded back to the
     * same JSON text the sender had, so callers never need to know which format was scanned.
     * @throws {Error} if parts are missing, the data does not match its id, or it is damaged
     */
    async result() {
        if (!this.isComplete()) throw new Error('Not all parts have been scanned yet.');
        if (this.plainText !== null) return this.plainText;

        let text = '';
        for (let i = 1; i <= this.total; i++) {
            text += this.parts.get(i);
        }
        const mismatch = () => new Error('The scanned parts do not fit together (checksum mismatch). Start over.');

        if (this.format === 'compact') {
            // Each part ends on a complete Base45 group, so the joined text is the Base45 of all bytes
            const bytes = SBO_Base45.decode(text);
            if (await SBO_QR.compactId(bytes) !== this.id) throw mismatch();
            return SBO_QRCompact.decode(bytes);
        }

        if (await SBO_QR.dataId(text) !== this.id) throw mismatch();
        return text;
    }
}

// Expose classes on globalThis, as crypto-utils.js does, so tests running in a VM can reach them
globalThis.SBO_QR          = SBO_QR;
globalThis.SBO_QRAssembler = SBO_QRAssembler;
globalThis.SBO_QRCompact   = SBO_QRCompact;
globalThis.SBO_Base45      = SBO_Base45;
