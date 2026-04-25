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

const SBO_AES_ALG_NAME="AES-CBC";
globalThis.SBO_AES_ALG_NAME = SBO_AES_ALG_NAME;
/*
async function createNewKeyPairs(keyName, password, ownerId){
    const rsaoaep = new SBORSAOAEP.RSAOAEP();

    const pkcs1 = new SBORSAPKCS1.RSASSAPKCS1v15();

    const encKeys = await rsaoaep.generateKeyPair();
    const signingKeys = await pkcs1.generateNewSigningKeyPair();


    const keyData = {
        enc: await exportCryptoKeyPairAsJwk(encKeys),
        sign: await exportCryptoKeyPairAsJwk(signingKeys),
        metadata:{
            created: new Date().toISOString(),
            name: keyName,
            owner: ownerId
        }
    }
    return keyData;
    
}

export async function encryptMyKeyPairs(keyData : object, password: string, currentUserEmail: string){
    const pbkdf = new SBOPBKDF.PBKDF2();
    const pbkdfCryptoKey = await pbkdf.generateKey(password, currentUserEmail, (password.length)^2);
    const txtEncoder = new TextEncoder();
    const saltBytes = txtEncoder.encode(password + currentUserEmail);
    const derivedIV = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: saltBytes, 
            iterations: (saltBytes.length)^2,
            hash: {name: "SHA-256"}
        },
            pbkdfCryptoKey, 
            128 
        );
    const keyDataJson = JSON.stringify(keyData);
    const cioherText = await window.crypto.subtle.encrypt(
        {name: "AES-CBC", iv:derivedIV},
        pbkdfCryptoKey,
        txtEncoder.encode(keyDataJson)
    );
    return cioherText;
}

export async function decryptMyKeys(cipherText : string, password : string, currentUserEmail: string){    
    const pbkdf = new SBOPBKDF.PBKDF2();
    const pbkdfCryptoKey = await pbkdf.generateKey(password, currentUserEmail, (password.length)^2);
    const txtEncoder = new TextEncoder();
    const saltBytes = txtEncoder.encode(password + currentUserEmail);
    const derivedIV = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: saltBytes, 
            iterations: (saltBytes.length)^2,
            hash: {name: "SHA-256"}
        },
            pbkdfCryptoKey, 
            128 
        );
    const plainTextBuffer = await window.crypto.subtle.decrypt(
        {name: "AES-CBC", iv:derivedIV},
        pbkdfCryptoKey,
        txtEncoder.encode(cipherText)
    );
    const txtDecoder = new TextDecoder();
    const plainText = await txtDecoder.decode(plainTextBuffer);
    return plainText;
}
*/