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
 * Web Worker that decodes QR codes with jsQR off the page's main thread.
 * A 1080p frame takes about half a second to decode, which would freeze the page.
 * Used only where the browser has no built-in BarcodeDetector.
 *
 * Message in:  { id, data: Uint8ClampedArray (RGBA pixels), width, height, thorough }
 * Message out: { id, texts: string[] }   or   { id, error: string }
 */

importScripts('vendor/jsqr/jsQR.js');

self.onmessage = function (event) {
    const msg = event.data;
    try {
        const result = jsQR(msg.data, msg.width, msg.height, {
            inversionAttempts: msg.thorough ? 'attemptBoth' : 'dontInvert'
        });
        self.postMessage({ id: msg.id, texts: result && result.data ? [result.data] : [] });
    } catch (err) {
        self.postMessage({ id: msg.id, error: String((err && err.message) || err) });
    }
};
