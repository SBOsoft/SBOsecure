/**
 * One-time script that generates RSA key pairs and contact fixtures for testing.
 * Run: node test/generate-fixtures.js
 */

import { webcrypto } from 'crypto'
import { writeFileSync, mkdirSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const { subtle } = webcrypto
const __dirname = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(__dirname, 'fixtures')

mkdirSync(fixturesDir, { recursive: true })

/** Generates a matched signing + encryption key pair set (mirrors CreateNewKeysForm) */
async function generateKeyset() {
    const signingPair = await subtle.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
        },
        true,
        ['sign', 'verify']
    )

    const encPair = await subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: 'SHA-256' }
        },
        true,
        ['encrypt', 'decrypt']
    )

    const [signPriv, signPub, encPriv, encPub] = await Promise.all([
        subtle.exportKey('jwk', signingPair.privateKey),
        subtle.exportKey('jwk', signingPair.publicKey),
        subtle.exportKey('jwk', encPair.privateKey),
        subtle.exportKey('jwk', encPair.publicKey)
    ])

    // Order matches createNewKeySet: signing first, encryption second
    return {
        public:  { keys: [signPub,  encPub]  },
        private: { keys: [signPriv, encPriv] }
    }
}

async function main() {
    console.log('Generating sender keyset (my keys)...')
    const senderKeyset = await generateKeyset()
    writeFileSync(join(fixturesDir, 'sender-keyset.jwks.json'), JSON.stringify(senderKeyset, null, 2))

    console.log('Generating recipient keyset (contact 1 — Alice)...')
    const aliceKeyset = await generateKeyset()
    writeFileSync(join(fixturesDir, 'recipient-keyset.jwks.json'), JSON.stringify(aliceKeyset, null, 2))

    // A single-contact file (Alice, using her public keys)
    const aliceContact = {
        name: 'Alice Test',
        notes: 'Primary test recipient',
        created: 1700000000,
        verifier: '',
        jwks: JSON.stringify({ keys: aliceKeyset.public.keys })
    }
    writeFileSync(join(fixturesDir, 'test-contact.json'), JSON.stringify(aliceContact, null, 2))

    // Three-contact file
    console.log('Generating Bob and Carol keysets (contacts 2 & 3)...')
    const bobKeyset   = await generateKeyset()
    const carolKeyset = await generateKeyset()

    const testContacts = [
        aliceContact,
        {
            name: 'Bob Test',
            notes: 'Second test recipient',
            created: 1700086400,
            verifier: '',
            jwks: JSON.stringify({ keys: bobKeyset.public.keys })
        },
        {
            name: 'Carol Test',
            notes: 'Third test recipient',
            created: 1700172800,
            verifier: '',
            jwks: JSON.stringify({ keys: carolKeyset.public.keys })
        }
    ]
    writeFileSync(join(fixturesDir, 'test-contacts.json'), JSON.stringify(testContacts, null, 2))

    console.log('Done. Fixtures written to', fixturesDir)
}

main().catch(err => { console.error(err); process.exit(1) })
