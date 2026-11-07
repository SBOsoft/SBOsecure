# SBOsecure

**Good enough security for ordinary people** — encrypt files and messages, sign your work, all inside your browser. No installation, no account, no data ever leaves your device.

---

## How it works

SBOsecure uses public-key cryptography. You have two keys:

- **Public key** — share this freely. Anyone with it can send you encrypted files.
- **Private key** (inside your keyset file) — keep this secret. Only you can decrypt what was sent to you.

Everything runs locally. The page has no server-side component and makes no network requests with your data.

---

## Getting started

### 1 — Create your keys (do this once)

1. Open the **My Keys** tab and click **Create new key**.
2. Enter a name, a password, and choose an iterations value (higher = more secure).
3. Click **Create new key set** and **immediately download the keyset file** — it will not be recoverable if you close the page without saving.
4. Download your **public key** (`public.jwks.json`) and share it with anyone who needs to send you encrypted files.

### 2 — Load your keys in future sessions

1. Go to **My Keys → Load key**.
2. Select your saved keyset file, enter your password and iterations number, then click **Load key**.

---

## Encrypting a message or file

1. Go to the **Contacts** tab and add the recipient — load their `public.jwks.json` file.
2. Open the **Encrypt** tab, type your message or select a file.
3. Check the recipient(s) you want to send to.
4. Click **Encrypt** and download the resulting `.sbo.json` file. Send it to the recipient by any means (email, messenger, file transfer).

> If your own keys are loaded, the package is automatically signed so the recipient can verify it came from you.

---

## Decrypting a package

1. Make sure your keys are loaded (**My Keys** tab).
2. Go to the **Decrypt** tab and either paste the `.sbo.json` content or load the file.
3. Click **Decrypt**. If the package was signed, SBOsecure will show whether the signature is valid.

---

## Password-based encryption

No keys required. Go to **Password Enc.** to encrypt or decrypt text with just a password. You must remember the exact password **and** the iterations number — both are needed to decrypt.

---

## QR codes

Public keys, encrypted packages and password-encrypted messages can be shown as QR codes (**QR code** next to Download) and read back with **Scan QR**, from the camera or from images. Large data is split over several codes, which can be scanned in any order. Scanning a contact's public key face to face, then comparing the key fingerprints, is the safest way to add a contact.

**Limits**

- About 800 bytes per code. A public key fits in 1 code, a short signed message in 2–3.
- Nothing over 10 KB is offered as QR codes (most encrypted files). Use Download instead.
- Your keyset is never offered as a QR code.

**Device differences**

- Chrome/Edge on Android, macOS and ChromeOS use the browser's built-in QR reader, which finds several codes in one image.
- Everywhere else (Windows, Linux, Firefox, Safari/iOS) the bundled [jsQR](webapp/DocumentRoot/vendor/README.md) reader is used. It finds one code per image and can be slower.
- Laptop webcams are front-facing and often low resolution: hold the code close so it fills most of the picture.
- Chrome and Edge on Windows can't read iPhone HEIC photos. Use screenshots or JPEG/PNG.
- The camera needs HTTPS and the user's permission. It turns off when the user leaves the scanning screen or the page is hidden.

**Privacy:** a QR code is a copy of the data, visible to anyone who can see or photograph it. That is fine for public keys and encrypted packages, but recipient names and file names in a package are readable without decryption, and a password-encrypted message is only as strong as its password. Camera frames and images are processed on the device only.

---

## Important notes

| | |
|---|---|
| **Keys are session-only** | Closing or refreshing the page clears loaded keys. Always save your keyset file. |
| **Keyset file is sensitive** | It contains your private key encrypted with your password. Treat it like a password manager file. |
| **Contacts are session-only** | Use **Download all** in the Contacts tab to save your contacts between sessions. |
| **HTTPS required** | Browser security requires the app to be served over HTTPS. It will not work over plain HTTP. |

---

## Cryptographic algorithms

SBOsecure uses standard algorithms provided by your browser's built-in Web Crypto API:
**AES-256-GCM** for content encryption · **RSA-OAEP-2048** for key wrapping · **RSASSA-PKCS1-v1_5** for signatures · **PBKDF2-SHA-256** for password-derived keys.

---

*SBOsecure is free software licensed under the GNU General Public License v3. Source: [github.com/SBOsoft/SBOsecure](https://github.com/SBOsoft/SBOsecure)*