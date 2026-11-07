import { describe, it, expect } from 'vitest'
import vm from 'vm'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

/** Loads ui.js in its own context; it only defines components, so no browser globals are needed */
function loadUi() {
    const ctx = vm.createContext({ console })
    vm.runInContext(readFileSync(join(__dirname, '../DocumentRoot/ui.js'), 'utf-8'), ctx)
    return ctx
}

describe('SBO_SanitizeContact', () => {
    const { SBO_SanitizeContact } = loadUi()

    it('keeps only known fields with the expected types', () => {
        const input = {
            name: 'Alice',
            notes: 'met at work',
            jwks: '{"keys":[]}',
            verifier: 'abc',
            created: 1700000000,
            isAdmin: true,
            __proto__: { polluted: true },
            extra: { nested: 1 }
        }
        const contact = SBO_SanitizeContact(input)
        expect(Object.keys(contact).sort()).toEqual(['created', 'jwks', 'name', 'notes', 'verifier'])
        expect(contact.polluted).toBeUndefined()
    })

    it('drops fields with the wrong type', () => {
        const contact = SBO_SanitizeContact({ name: 'Bob', jwks: { keys: [] }, notes: 5, created: '2024' })
        expect(contact).toEqual({ name: 'Bob' })
    })

    it('rejects values that are not usable contacts', () => {
        expect(SBO_SanitizeContact(null)).toBeNull()
        expect(SBO_SanitizeContact('Alice')).toBeNull()
        expect(SBO_SanitizeContact([{ name: 'Alice' }])).toBeNull()
        expect(SBO_SanitizeContact({ notes: 'no name, no keys' })).toBeNull()
        expect(SBO_SanitizeContact({ name: '', jwks: '' })).toBeNull()
    })

    it('accepts a contact with keys but no name', () => {
        expect(SBO_SanitizeContact({ jwks: '{"keys":[]}' })).toEqual({ jwks: '{"keys":[]}' })
    })
})
