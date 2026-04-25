/**
 * Loads the browser-global source files into a VM context so tests can use them
 * without a real browser. The VM context provides window.crypto via Node's webcrypto.
 *
 * Usage:
 *   import { getClasses } from './setup.js'
 *   const { SBO_AESEncrypt, SBO_RSAOAEP, ... } = getClasses()
 */

import vm from 'vm'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { webcrypto } from 'crypto'

const __dirname = dirname(fileURLToPath(import.meta.url))
const docRoot = join(__dirname, '../DocumentRoot')

let _ctx = null

export function getClasses() {
    if (_ctx) return _ctx

    // Provide the browser globals the source files rely on.
    // The source files assign each class to globalThis, and in a VM context
    // globalThis IS the sandbox object — so the classes land here automatically.
    const sandbox = {
        window: { crypto: webcrypto },
        crypto: webcrypto,
        TextEncoder,
        TextDecoder,
        console
    }
    const ctx = vm.createContext(sandbox)

    for (const file of ['crypto.js', 'crypto-utils.js']) {
        vm.runInContext(readFileSync(join(docRoot, file), 'utf-8'), ctx)
    }

    _ctx = ctx
    return _ctx
}

/** Convenience: import a JWK signing private key using the loaded class */
export async function importSigningPrivateKey(jwk) {
    const { SBO_RSASSAPKCS1v15 } = getClasses()
    return new SBO_RSASSAPKCS1v15().importSigningPrivateKey(jwk)
}

/** Convenience: import a JWK RSA-OAEP public key using the loaded class */
export async function importEncPublicKey(jwk) {
    const { SBO_RSAOAEP } = getClasses()
    return new SBO_RSAOAEP().importJwkPublicKey(jwk)
}

/** Convenience: import a JWK RSA-OAEP private key using the loaded class */
export async function importEncPrivateKey(jwk) {
    const { SBO_RSAOAEP } = getClasses()
    return new SBO_RSAOAEP().importJwkPrivateKey(jwk)
}
