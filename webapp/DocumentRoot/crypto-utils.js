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

class SBO_Base64 {
    lookup = [];
    revLookup = [];
    Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array;
    code = '';

    constructor(isUrlSafe) {
        if(isUrlSafe){
            this.code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        }
        else{
            this.code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        }
        for (let i = 0, len = this.code.length; i < len; ++i) {
            this.lookup[i] = this.code[i];
            this.revLookup[this.code.charCodeAt(i)] = i;
        }
        if(isUrlSafe){
            this.revLookup['-'.charCodeAt(0)] = 62;
            this.revLookup['_'.charCodeAt(0)] = 63;
        }

    }

    placeHoldersCount(b64EncodedString) {
        const len = b64EncodedString.length;
        if (len % 4 > 0) {
            throw new Error('Invalid string. Length must be a multiple of 4');
        }

        // the number of equal signs (place holders)
        // if there are two placeholders, than the two characters before it
        // represent one byte
        // if there is only one, then the three characters before it represent 2 bytes
        return b64EncodedString[len - 2] === '=' ? 2 : b64EncodedString[len - 1] === '=' ? 1 : 0;
    }

    byteLength(b64EncodedString) {
        // base64 is 4/3 of original data + up to two characters length
        return (b64EncodedString.length * 3 / 4) - this.placeHoldersCount(b64EncodedString);
    }

    
    decodeAsString(b64EncodedString){
        const decodedBytes = this.decodeAsByteArray(b64EncodedString);
        const txtdecoder = new TextDecoder('utf-8');
        const decodedStr = txtdecoder.decode(decodedBytes);
        return decodedStr;
    }

    decodeAsByteArray(b64) {
        const len = b64.length;
        const placeHolders = this.placeHoldersCount(b64);

        const arr = new this.Arr((len * 3 / 4) - placeHolders);

        // if there are placeholders, only get up to the last complete 4 chars
        let l = placeHolders > 0 ? len - 4 : len;

        let L = 0;
        let tmp;
        let i;

        for (i = 0; i < l; i += 4) {
            tmp = (this.revLookup[b64.charCodeAt(i)] << 18) | (this.revLookup[b64.charCodeAt(i + 1)] << 12) |
                    (this.revLookup[b64.charCodeAt(i + 2)] << 6) | this.revLookup[b64.charCodeAt(i + 3)]
            arr[L++] = (tmp >> 16) & 0xFF;
            arr[L++] = (tmp >> 8) & 0xFF;
            arr[L++] = tmp & 0xFF;
        }

        if (placeHolders === 2) {
            tmp = (this.revLookup[b64.charCodeAt(i)] << 2) | (this.revLookup[b64.charCodeAt(i + 1)] >> 4)
            arr[L++] = tmp & 0xFF;
        } else if (placeHolders === 1) {
            tmp = (this.revLookup[b64.charCodeAt(i)] << 10) | (this.revLookup[b64.charCodeAt(i + 1)] << 4)
                    | (this.revLookup[b64.charCodeAt(i + 2)] >> 2)
            arr[L++] = (tmp >> 8) & 0xFF;
            arr[L++] = tmp & 0xFF;
        }

        return arr;
    }
    
    tripletToBase64(num) {
        return this.lookup[num >> 18 & 0x3F] + this.lookup[num >> 12 & 0x3F] + this.lookup[num >> 6 & 0x3F]
                + this.lookup[num & 0x3F];
    }

    encodeChunk(uint8, start, end) {
        let tmp;
        const output = [];
        for (let i = start; i < end; i += 3) {
            tmp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2]);
            output.push(this.tripletToBase64(tmp));
        }
        return output.join('')
    }

    encodeBytes(uint8) {
        let tmp;
        const len = uint8.length;
        const extraBytes = len % 3; // if we have 1 byte left, pad 2 bytes
        let output = '';
        const parts = [];
        const maxChunkLength = 16383; // must be multiple of 3

        // go through the array every three bytes, we'll deal with trailing stuff later
        for (let i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
            parts.push(this.encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
        }

        // pad the end with zeros, but make sure to not forget the extra bytes
        if (extraBytes === 1) {
            tmp = uint8[len - 1]
            output += this.lookup[tmp >> 2]
            output += this.lookup[(tmp << 4) & 0x3F]
            output += '=='
        } else if (extraBytes === 2) {
            tmp = (uint8[len - 2] << 8) + (uint8[len - 1]);
            output += this.lookup[tmp >> 10];
            output += this.lookup[(tmp >> 4) & 0x3F];
            output += this.lookup[(tmp << 2) & 0x3F];
            output += '=';
        }

        parts.push(output);
        return parts.join('');
    }
   
    
    encodeString(str){
        const txtencoder = new TextEncoder();
        const bytes = txtencoder.encode(str);
        return this.encodeBytes(bytes);
    }
}

class SBO_CryptoUtils {
    static hexEncode(uint8arrayinstance){
        let hex, i;
        let result = "";
        for (i=0; i<uint8arrayinstance.length; i++) {
            hex = uint8arrayinstance[i].toString(16);
            result += ("00"+hex).slice(-2);
        }
        return result;
    }
    /**
     * @param {Number} bytesLength
     * @returns {Uint8Array}
     */
    static getRandomBytes(bytesLength){
        const buffer = new Uint8Array(bytesLength);
        window.crypto.getRandomValues(buffer);
        return buffer;
    }


    /**
     * @returns {ArrayBuffer}
     */
    static async sha256(inputStr){
        const txtencoder = new TextEncoder();
        const inputBuffer = txtencoder.encode(inputStr);
        return await window.crypto.subtle.digest("SHA-256", inputBuffer);        
    }

    static sha256ToUserFriendlyCheckValues(hashBuffer){
        const uint8array = new Uint8Array(hashBuffer);
        let sum = 0;
        const fourpiecesum = [0,0,0,0];
        for(let i=0;i<uint8array.length;i++){
            sum += uint8array[i];
            fourpiecesum[i%4]=fourpiecesum[i%4]+uint8array[i];
        }
        const hashstr = SBO_CryptoUtils.hexEncode(uint8array);
        const splithash = hashstr.match(/.{1,2}/g);

        const rv ={
            checksum: sum,
            foursum : fourpiecesum.join('-'),
            hash: splithash
        };
        return rv;
    }
    


    /**
     * @returns {JsonWebKey}
     */
    static async exportCryptoKeyAsJwk(cryptoKey){
        const keyJwk = await window.crypto.subtle.exportKey('jwk', cryptoKey);
        return keyJwk;
    }

    /**
     * @returns Object with privateKeyJwk and publicKeyJwk fields
     */
    static async exportCryptoKeyPairAsJwk(cryptoKeyPair){
        const privateKeyJwk = await window.crypto.subtle.exportKey('jwk', cryptoKeyPair.privateKey);
        const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', cryptoKeyPair.publicKey);
        return {
            privateKeyJwk: privateKeyJwk,
            publicKeyJwk: publicKeyJwk
        };
    }

} //class SBO_CryptoUtils

class SBO_RSAOAEP{
    algorithm = {
        name: "RSA-OAEP",
        modulusLength: 2048, 
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {name: "SHA-256"}
    };
    signatureAlgo ='HMAC';
    encryptDecryptAlgo = {"name": "RSA-OAEP"};

    constructor(){        
    }

    async generateKeyPair(){
        const usages = ["encrypt", "decrypt"];  // Array<KeyUsage>
        const keyPair = await window.crypto.subtle.generateKey(this.algorithm, true, usages);   //CryptoKeyPair
        return {
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey
        }
    }

    async importPkcs8(keyData /* BufferSource */ ){
        const usages = ["decrypt"];  //Array<KeyUsage> — private key can only decrypt
        //CryptoKey
        const key = await window.crypto.subtle.importKey('pkcs8', keyData, this.algorithm, true, usages);
        return key;
    }

    async importJwkPrivateKey(keyJwk /* JsonWebKey */){
        const usages = ["decrypt"];  //Array<KeyUsage> — private key can only decrypt
        //CryptoKey
        const importedKey = await window.crypto.subtle.importKey('jwk', keyJwk, this.algorithm, false, usages);
        return importedKey;
    }

    async importJwkPublicKey(keyJwk /* JsonWebKey */){
        const usages = ["encrypt"]; //Array<KeyUsage>
        //CryptoKey
        const importedKey = await window.crypto.subtle.importKey('jwk', keyJwk, this.algorithm, false, usages);
        return importedKey;
    }
    
    async encrypt(publicKey /* CryptoKey */, plainTextBuffer /* BufferSource */){
        //ArrayBuffer
        const cipherBuffer = await window.crypto.subtle.encrypt(this.encryptDecryptAlgo, publicKey, plainTextBuffer);
        return cipherBuffer;
    }
    
    async decrypt(privateKey /* CryptoKey */, cipherBuffer /* BufferSource */){
        //ArrayBuffer
        const plainTextBuffer = await window.crypto.subtle.decrypt(this.encryptDecryptAlgo, privateKey, cipherBuffer);
        return plainTextBuffer;
    }    

} 

class SBO_AESEncrypt {
    ciphertextBuffer = null;
    iv = null;

    constructor() {

    }


    async encrypt(inputBufferSource, algName, aesCryptoKey /* CryptoKey */ , ivOptionalByteArray) {
        if (ivOptionalByteArray){
            this.iv = ivOptionalByteArray;
        }
        else{
            this.iv = SBO_CryptoUtils.getRandomBytes(12);
        }
        
        const alg = {
            name: algName,
            iv: this.iv
        };
        this.ciphertextBuffer = await window.crypto.subtle.encrypt(alg, aesCryptoKey, inputBufferSource);
        return true;
    }

    getCipherTextBase64Encoded() {
        if (this.ciphertextBuffer) {
            const uint8array = new Uint8Array(this.ciphertextBuffer);
            const b64 = new SBO_Base64(false);
            const rv = b64.encodeBytes(uint8array);
            return rv;
        } 
        else {
            console.log('this.ciphertextBuffer is null in SBO_AESEncrypt.getCipherTextBase64Encoded');
            return null;
        }
    }
    
    getIVBase64Encoded() {
        if (this.iv) {
            const uint8array = new Uint8Array(this.iv);
            const b64 = new SBO_Base64(false);
            const rv = b64.encodeBytes(uint8array);
            return rv;
        } 
        else {
            console.log('this.iv is null in SBO_AESEncrypt.getIVBase64Encoded');
            return null;
        }
    }

}

class SBO_AESDecrypt{
    
    static async decrypt(ciphertextBase64Encoded /* string */, ivDataB64Encoded /* string */, aesCryptoKey /* CryptoKey */, aesAlgName /* string */){
        try{
            const b64 = new SBO_Base64(false);
            const ivBytes = b64.decodeAsByteArray(ivDataB64Encoded);

            const algo =  {name: aesAlgName, iv: ivBytes};
            const ciphertextBytes = b64.decodeAsByteArray(ciphertextBase64Encoded);
            //ArrayBuffer
            const plainTextBuffer = await window.crypto.subtle.decrypt(algo, aesCryptoKey, ciphertextBytes);
            const txtDecoder = new TextDecoder();
            const rv = txtDecoder.decode(plainTextBuffer);
            return rv;
        }
        catch(ex){
            console.log("SBO_AESDecrypt.decrypt failed");
            console.log(ex);
            return null;
        }
    }
    
    
    static async decrypt2(ciphertextBase64Encoded /* string */, ivData /* ArrayBuffer */, aesCryptoKey /* CryptoKey */, aesAlgName /* string */){
        try{
            const b64 = new SBO_Base64(false);

            const algo =  {name: aesAlgName, iv: ivData};
            const ciphertextBytes = b64.decodeAsByteArray(ciphertextBase64Encoded);
            //ArrayBuffer
            const plainTextBuffer = await window.crypto.subtle.decrypt(algo, aesCryptoKey, ciphertextBytes);
            const txtDecoder = new TextDecoder();
            const rv = txtDecoder.decode(plainTextBuffer);
            return rv;
        }
        catch(ex){
            console.log("SBO_AESDecrypt.decrypt failed");
            console.log(ex);
            return null;
        }
    }
    
}

class SBO_PBKDF2{

    /**
     * 
     * @param {string} password
     * @param {string} salt
     * @param {number} iterations
     * @param {string} aesAlgName
     * @returns {CryptoKey} 
     */
    static async generateKey(password /* string */, salt /* string */, iterations /* number */, aesAlgName /* string */){
        const usages = ['deriveBits', 'deriveKey']; //Array<KeyUsage>
        const txtEncoder = new TextEncoder();
        const passwordBuffer = txtEncoder.encode(password);
        const saltBuffer = txtEncoder.encode(salt);
        //CryptoKey
        const keyFromPassword = await window.crypto.subtle.importKey('raw', passwordBuffer, {name: 'PBKDF2'}, false, usages);
        //CryptoKey
        const derivedKey = await window.crypto.subtle.deriveKey(
            { "name": 'PBKDF2', "salt": saltBuffer, "iterations": iterations, "hash": 'SHA-256'},
            keyFromPassword,
            { "name": aesAlgName, "length": 128 },
            true,
            [ "encrypt", "decrypt" ]);
        //const exportedKey : CryptoKey = await window.crypto.subtle.exportKey('raw', derivedKey);
        return derivedKey;
    }


    static async generateIVForAES(password /* string */, salt /* string */, iterations /* number */){
        var txtEncoder = new TextEncoder();
        let passwordBuffer = txtEncoder.encode(password);
        let saltBuffer = null; 
        if(ArrayBuffer.isView(salt)){
            saltBuffer = salt;
        }
        else{
            saltBuffer = txtEncoder.encode(salt);
        }
        
        
        let importedKey = await window.crypto.subtle.importKey('raw', passwordBuffer, {name: 'PBKDF2'}, false, ['deriveBits', 'deriveKey']);
        return window.crypto.subtle.deriveBits(
        {
            "name": "PBKDF2",
            salt: saltBuffer,
            iterations: iterations+ (101) + (iterations/3),
            hash: {name: "SHA-256"}
        },
            importedKey, 
            128
        );
    }

    
    
    
}   //end of SBO_PBKDF2


class SBO_RSASSAPKCS1v15 {
    algorithm = {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048, 
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {name: "SHA-256"}
    };
    
    signatureAlgo ='RSASSA-PKCS1-v1_5';

    constructor(){        
    }

    /**
     * @return Object 
     */
    async generateNewSigningKeyPair() {
        //Array<KeyUsage>
        const usages = ["sign", "verify"];
        //CryptoKeyPair 
        const keyPair = await window.crypto.subtle.generateKey(this.algorithm, true, usages);

        return {
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey
        };
    }

    /**
     * @return CryptoKey
     */
    async importSigningPrivateKey(keyJwk /* JsonWebKey */){
        //Array<KeyUsage>
        const usages = ["sign"];
        //CryptoKey
        const importedKey = await window.crypto.subtle.importKey('jwk', keyJwk, this.algorithm, false /* not extractable */, usages);
        return importedKey;
    }

    /**
     * @return CryptoKey
     */
    async importVerificationPublicKey(keyJwk /* JsonWebKey */){
        //Array<KeyUsage> 
        const usages = ["verify"];
        //CryptoKey 
        const importedKey = await window.crypto.subtle.importKey('jwk', keyJwk, this.algorithm, false /* not extractable */, usages);
        return importedKey;
    }

    /**
     * @return ArrayBuffer
     */
    async sign(privateKey /* CryptoKey */, stringToBeSigned /* string */)
    {
        const txtEncoder = new TextEncoder();
        const bytesToSign = txtEncoder.encode(stringToBeSigned);
        //ArrayBuffer
        const signature = await window.crypto.subtle.sign(this.signatureAlgo, privateKey, bytesToSign);
        return signature;
    }
    
    /**
     * @return boolean
     */
    async verifySignature(publicKey /* CryptoKey */, signature /* BufferSource */, stringToBeSigned /* string */)
    {
        const txtEncoder = new TextEncoder();
        const bytesToSign = txtEncoder.encode(stringToBeSigned);
        //boolean
        const isValid = await window.crypto.subtle.verify(this.signatureAlgo, publicKey, signature, bytesToSign);
        return isValid;
    }

}   //end of SBO_RSASSAPKCS1v15

// Expose classes on globalThis so they are reachable in any execution context:
// browser (<script> tag → globalThis is window), Node.js VM sandbox, etc.
globalThis.SBO_Base64             = SBO_Base64;
globalThis.SBO_CryptoUtils        = SBO_CryptoUtils;
globalThis.SBO_RSAOAEP            = SBO_RSAOAEP;
globalThis.SBO_AESEncrypt         = SBO_AESEncrypt;
globalThis.SBO_AESDecrypt         = SBO_AESDecrypt;
globalThis.SBO_PBKDF2             = SBO_PBKDF2;
globalThis.SBO_RSASSAPKCS1v15     = SBO_RSASSAPKCS1v15;

//async function SBO_ImportPrivateKey(jwk){
//    let importParams;
//    if (jwk.kty === 'RSA') {
//        importParams = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
//    } else if (jwk.kty === 'EC') {
//        importParams = { name: "ECDSA", namedCurve: jwk.crv };
//    } else if (jwk.kty === 'OKP') {
//        importParams = { name: "Ed25519" };
//    } else {
//        throw new Error("Unsupported Key Type (kty): " + jwk.kty);
//    }
//    switch(jwk.kty){
//        case 'RSA':
//            break;
//    }
//    const importedKey = await window.crypto.subtle.importKey('jwk', jwk, , false /* not extractable */, usages);
//}