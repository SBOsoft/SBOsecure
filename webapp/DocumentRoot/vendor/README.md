# Vendored libraries

Third-party code is kept in the repository instead of being loaded from a CDN, so the
code that handles user data is always the reviewed copy below. Neither library makes
network requests or touches the DOM, storage or `eval`.

| Library | Version | Licence | Used for |
|---|---|---|---|
| [QR Code generator](https://www.nayuki.io/page/qr-code-generator-library) by Project Nayuki | 1.8.0 | MIT (header of `qrcodegen.js`) | Generating QR codes |
| [jsQR](https://github.com/cozmo/jsQR) by Cosmo Wolfe | 1.4.0 | Apache-2.0 (`jsqr/LICENSE`) | Reading QR codes when the browser has no `BarcodeDetector`. Loaded only when needed. |

## Provenance

### qrcodegen/qrcodegen.js

- Source: `typescript-javascript/qrcodegen.ts` at tag `v1.8.0` of
  https://github.com/nayuki/QR-Code-generator
  (SHA-256 `c4749095a91bf9696e3a303998b9905e467094f53041e64393e65e6d887737fd`)
- Compiled with TypeScript 5.6.3: `tsc --target ES2017 --strict qrcodegen.ts`
- Output SHA-256 `6e200897a80ff15a652a5d601667856d807cec60cfc81a3a351305d69cc9dbbd`

### jsqr/jsQR.js

- Source: `dist/jsQR.js` from the npm package `jsqr@1.4.0`
- SHA-256 `bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859`

To check the files: `sha256sum vendor/qrcodegen/qrcodegen.js vendor/jsqr/jsQR.js`
