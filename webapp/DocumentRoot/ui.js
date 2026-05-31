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

const DownloadableItem = {
    props: ['fileName', 'mimeType', 'itemData', 'dataType'],
    methods:{
        download() {
            SBO_SaveAsFile(this.itemData, this.fileName, this.mimeType || 'application/octet-stream');
        },
        async copy(){
            await navigator.clipboard.writeText(this.itemData);
        }
    },
    template: `<div class="d-inline-block d-flex justify-content-between">
    <button v-on:click="copy" class="btn btn-sm btn-outline-light">
        <img src="img/copy.svg" border="0"> 
        Copy
    </button>
    <button v-on:click="download" class="btn btn-sm btn-outline-light">
        <img src="img/download.svg" border="0">
        Download
    </button>
    
</div>`   
};


const PBKDFEncryptDecrypt = {
    props:[],
    data: function () {
        return {
            pbkdfMode: null,
            pbkdfPasswordVisible: false,
            pbkdfPassword: '',
            pbkdfIterations: 600000,
            pbkdfCipherText: '',
            pbkdfIV: '',
            pbkdfSalt: '',
            pbkdfPlainText: '',
            pbkdfDecryptFailed: false,
            pbkdfPackage: null,
            pbkdfLoadError: null,
            pbkdfError: null
        };
    },
    methods:{
        togglePbkdfPassword(){
            this.pbkdfPasswordVisible = !this.pbkdfPasswordVisible;
        },
        goBack(){
            this.pbkdfMode = null;
            this.pbkdfPassword = '';
            this.pbkdfPasswordVisible = false;
            this.pbkdfPlainText = '';
            this.pbkdfCipherText = '';
            this.pbkdfIV = '';
            this.pbkdfSalt = '';
            this.pbkdfPackage = null;
            this.pbkdfDecryptFailed = false;
            this.pbkdfLoadError = null;
            this.pbkdfError = null;
        },
        validIterations(val){
            const n = Number(val);
            return Number.isInteger(n) && n >= 600000 && n <= 1000000;
        },
        async pbkdfDecrypt(){
            this.pbkdfError = null;
            this.pbkdfDecryptFailed = false;
            this.pbkdfPlainText = '';
            if (!this.pbkdfCipherText) {
                this.pbkdfError = 'Load an encrypted package file first.';
                return;
            }
            if (!this.pbkdfPassword) {
                this.pbkdfError = 'Enter a password.';
                return;
            }
            if (!this.validIterations(this.pbkdfIterations)) {
                this.pbkdfError = 'Iterations must be a whole number between 600,000 and 1,000,000.';
                return;
            }
            const b64 = new SBO_Base64(false);
            let salt = b64.decodeAsByteArray(this.pbkdfSalt);
            let cryptoKeyForPbkdf = await SBO_PBKDF2.generateKey(this.pbkdfPassword, salt, this.pbkdfIterations, SBO_AES_ALG_NAME);
            let plainText = await SBO_AESDecrypt.decrypt(this.pbkdfCipherText, this.pbkdfIV, cryptoKeyForPbkdf, SBO_AES_ALG_NAME);
            if(!plainText) {
                this.pbkdfDecryptFailed = true;
            }
            this.pbkdfPlainText = plainText;
        },
        /*
         * both salt and IV are random. users must store them too along with the cipher text
         */
        async pbkdfEncrypt(){
            this.pbkdfPackage = null;
            this.pbkdfError = null;
            if (!this.pbkdfPlainText.trim()) {
                this.pbkdfError = 'Enter a message to encrypt.';
                return;
            }
            if (!this.pbkdfPassword) {
                this.pbkdfError = 'Enter a password.';
                return;
            }
            if (!this.validIterations(this.pbkdfIterations)) {
                this.pbkdfError = 'Iterations must be a whole number between 600,000 and 1,000,000.';
                return;
            }
            let salt = SBO_CryptoUtils.getRandomBytes(16);
            let cryptoKeyForPbkdf = await SBO_PBKDF2.generateKey(this.pbkdfPassword, salt, this.pbkdfIterations, SBO_AES_ALG_NAME);
            let aesEnc = new SBO_AESEncrypt();
            const utf8encoder = new TextEncoder();
            let uint8ArrayFromPlainText = utf8encoder.encode(this.pbkdfPlainText);
            await aesEnc.encrypt(uint8ArrayFromPlainText, SBO_AES_ALG_NAME, cryptoKeyForPbkdf);
            const b64 = new SBO_Base64(false);
            this.pbkdfCipherText = aesEnc.getCipherTextBase64Encoded();
            this.pbkdfIV = aesEnc.getIVBase64Encoded();
            this.pbkdfSalt = b64.encodeBytes(salt);
            this.pbkdfPackage = JSON.stringify({
                version: 1,
                type: 'sbo-pbkdf-encrypted',
                encryptedContent: {
                    ciphertext: this.pbkdfCipherText,
                    iv: this.pbkdfIV
                },
                pbkdf: {
                    salt: this.pbkdfSalt
                }
            });
        },
        downloadPbkdfPackage(){
            SBO_SaveAsFile(this.pbkdfPackage, 'encrypted-message.sbo.json', 'application/json');
        },
        loadPbkdfPackageFile(event){
            this.pbkdfLoadError = null;
            const file = event.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const pkg = JSON.parse(e.target.result);
                    if (pkg.type !== 'sbo-pbkdf-encrypted') {
                        this.pbkdfLoadError = 'Not a password-encrypted package. Use the Decrypt tab for public-key packages.';
                        return;
                    }
                    this.pbkdfCipherText = pkg.encryptedContent.ciphertext;
                    this.pbkdfIV        = pkg.encryptedContent.iv;
                    this.pbkdfSalt      = pkg.pbkdf.salt;
                    this.pbkdfPackage   = null;
                    this.pbkdfPlainText = '';
                    this.pbkdfDecryptFailed = false;
                } catch {
                    this.pbkdfLoadError = 'Could not parse file.';
                }
                event.target.value = '';
            };
            reader.readAsText(file);
        }
    },
    template: `<div>

<!-- ── Mode selector ──────────────────────────────────── -->
<div v-if="pbkdfMode === null" class="row g-3 mt-1">
    <div class="col-sm-6">
        <div class="border rounded p-4 text-center h-100" style="cursor:pointer"
             v-on:click="pbkdfMode = 'encrypt'">
            <i class="bi bi-lock-fill fs-1 text-warning d-block mb-2"></i>
            <div class="fw-semibold">Encrypt a message</div>
            <div class="text-secondary small mt-1">Lock text with a password. Share the resulting file with the recipient.</div>
        </div>
    </div>
    <div class="col-sm-6">
        <div class="border rounded p-4 text-center h-100" style="cursor:pointer"
             v-on:click="pbkdfMode = 'decrypt'">
            <i class="bi bi-unlock-fill fs-1 text-primary d-block mb-2"></i>
            <div class="fw-semibold">Decrypt a message</div>
            <div class="text-secondary small mt-1">Open a password-encrypted package file to read its contents.</div>
        </div>
    </div>
</div>

<!-- ── Encrypt screen ─────────────────────────────────── -->
<div v-if="pbkdfMode === 'encrypt'">
    <a href="#" class="small text-secondary d-inline-block mb-3" v-on:click.prevent="goBack()">
        <i class="bi bi-arrow-left me-1"></i>Back
    </a>
    <div class="mb-3">
        <label class="form-label" for="pbkdfPlainText">Message</label>
        <textarea v-model="pbkdfPlainText" id="pbkdfPlainText" class="form-control" rows="6"
                  placeholder="Enter the text you want to encrypt…"></textarea>
    </div>
    <div class="mb-3">
        <label class="form-label" for="pbkdfEncPassword">Password</label>
        <div class="input-group">
            <input v-model="pbkdfPassword"
                   v-bind:type="pbkdfPasswordVisible ? 'text' : 'password'"
                   class="form-control" id="pbkdfEncPassword">
            <i class="input-group-text" style="cursor:pointer"
               v-bind:class="pbkdfPasswordVisible ? 'bi bi-eye' : 'bi bi-eye-slash'"
               v-on:click="togglePbkdfPassword()"></i>
        </div>
    </div>
    <div class="mb-3">
        <label class="form-label">Iterations</label>
        <input v-model.number="pbkdfIterations" type="number" min="600000" max="1000000" step="1000" class="form-control">
        <div class="form-text">The recipient must use the same number to decrypt.</div>
    </div>
    <div class="mb-3">
        <button type="button" v-on:click="pbkdfEncrypt" class="btn btn-warning">
            <i class="bi bi-lock-fill me-1"></i>Encrypt
        </button>
    </div>
    <div v-if="pbkdfError" class="alert alert-danger py-2">{{ pbkdfError }}</div>
    <div v-if="pbkdfPackage" class="alert alert-success d-flex align-items-center gap-3">
        <i class="bi bi-check-circle-fill fs-5"></i>
        <div class="flex-fill">Encryption successful.</div>
        <button type="button" v-on:click="downloadPbkdfPackage" class="btn btn-success btn-sm">
            <i class="bi bi-download me-1"></i>Download package
        </button>
    </div>
</div>

<!-- ── Decrypt screen ─────────────────────────────────── -->
<div v-if="pbkdfMode === 'decrypt'">
    <a href="#" class="small text-secondary d-inline-block mb-3" v-on:click.prevent="goBack()">
        <i class="bi bi-arrow-left me-1"></i>Back
    </a>
    <div class="mb-3">
        <label class="form-label">Encrypted package file</label>
        <label class="btn btn-secondary d-block text-start" style="cursor:pointer">
            <i class="bi bi-folder2-open me-2"></i>Load encrypted package…
            <input type="file" accept=".json" class="d-none" v-on:change="loadPbkdfPackageFile">
        </label>
        <div v-if="pbkdfLoadError" class="form-text text-danger mt-1">{{ pbkdfLoadError }}</div>
    </div>
    <div v-if="pbkdfCipherText" class="alert alert-info d-flex align-items-center gap-2 py-2 mb-3">
        <i class="bi bi-file-earmark-lock-fill"></i>
        <div>Package loaded — enter your password and iterations to decrypt.</div>
    </div>
    <div class="mb-3">
        <label class="form-label">Iterations</label>
        <input v-model.number="pbkdfIterations" type="number" min="600000" max="1000000" step="1000" class="form-control">
        <div class="form-text">Must match the value used when encrypting.</div>
    </div>
    <div class="mb-3">
        <label class="form-label" for="pbkdfDecPassword">Password</label>
        <div class="input-group">
            <input v-model="pbkdfPassword"
                   v-bind:type="pbkdfPasswordVisible ? 'text' : 'password'"
                   class="form-control" id="pbkdfDecPassword">
            <i class="input-group-text" style="cursor:pointer"
               v-bind:class="pbkdfPasswordVisible ? 'bi bi-eye' : 'bi bi-eye-slash'"
               v-on:click="togglePbkdfPassword()"></i>
        </div>
    </div>
    <div class="mb-3">
        <button type="button" v-on:click="pbkdfDecrypt" class="btn btn-primary">
            <i class="bi bi-unlock-fill me-1"></i>Decrypt
        </button>
    </div>
    <div v-if="pbkdfError" class="alert alert-danger py-2">{{ pbkdfError }}</div>
    <div v-if="pbkdfDecryptFailed" class="alert alert-danger">
        <i class="bi bi-x-circle-fill me-1"></i>
        Decryption failed. Check that you are using the correct password and the correct file.
    </div>
    <div v-if="pbkdfPlainText" class="mb-3">
        <label class="form-label">Decrypted message</label>
        <textarea v-bind:value="pbkdfPlainText" class="form-control" rows="6" readonly></textarea>
    </div>
</div>

</div>`

};


const Base64Form = {
    data() {
        return {
            base64Output: '',
            base64Input: '',
            base64Failed:false
        }
    },
    methods:{
        base64Encode(){
            const b64 = new SBO_Base64(false);
            this.base64Output = b64.encodeString(this.base64Input);
        },
        base64Decode(){
            const b64 = new SBO_Base64(false);
            this.base64Output = b64.decodeAsString(this.base64Input);
        }  
    },
    template:`<div>
<div class="my-2"> 
    <label class="form-label" for="base64Input">Input</label>
    <textarea v-model="base64Input" name="base64Input" id="base64Input" class="form-control"></textarea>                                
</div>
<div class="my-2 text-center">
    <button type="button" v-on:click="base64Encode" class="btn btn-warning ms-2 ">Encode</button>
    <button type="button" v-on:click="base64Decode" class="btn btn-primary ms-2 ">Decode</button>
</div>
<div class="my-2"> 
    <label class="form-label" for="base64Output">Output</label>
    <textarea v-model="base64Output" name="base64Output" id="base64Output" class="form-control"></textarea>
    <div class="form-text text-danger" v-if="base64Failed">Base64 operation failed</div>
</div>
</div>
`
};

const LoadMyKeysForm = {
    props:['keysLoadedCallback'],
    data(){
        return {
            loadKeyPastedText: '',
            loadKeyPassword: '',
            loadKeyIterations: 600000,
            loadKeyPasswordVisible: false,
            loadKeyError: null
        }
    },
    methods:{
        toggleLoadKeyPassword(){
            this.loadKeyPasswordVisible = !this.loadKeyPasswordVisible;
        },
        loadKeyFileSelected(event){
            const file = event.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    const textContent = e.target.result;
                    this.loadKeyPastedText = textContent;
                    this.loadKeyError = null;
                };
                reader.readAsText(file);
            }
        },
        validIterations(val) {
            const n = Number(val);
            return Number.isInteger(n) && n >= 600000 && n <= 1000000;
        },
        async loadKeySet(){
            this.loadKeyError = null;
            if (!this.loadKeyPastedText.trim()) {
                this.loadKeyError = 'Select a key file or paste the key content.';
                return;
            }
            if (!this.loadKeyPassword) {
                this.loadKeyError = 'Enter a password.';
                return;
            }
            if (!this.validIterations(this.loadKeyIterations)) {
                this.loadKeyError = 'Iterations must be a whole number between 600,000 and 1,000,000.';
                return;
            }
            let keySetJson;
            try {
                keySetJson = JSON.parse(this.loadKeyPastedText);
            } catch {
                this.loadKeyError = 'Invalid key file — could not parse JSON.';
                return;
            }

            //keySetJson.jwks is base64 encoded pbkdf encrypted jwks
            const b64 = new SBO_Base64(false);
            let salt = b64.decodeAsByteArray(keySetJson.salt);
            let cryptoKeyForPbkdf = await SBO_PBKDF2.generateKey(this.loadKeyPassword, salt, this.loadKeyIterations, SBO_AES_ALG_NAME);

            let plainText = await SBO_AESDecrypt.decrypt(keySetJson.jwks, keySetJson.iv, cryptoKeyForPbkdf, SBO_AES_ALG_NAME);
            if (plainText) {
                let parsedJwks = JSON.parse(plainText);
                this.keysLoadedCallback(keySetJson, parsedJwks);
            } else {
                this.loadKeyError = 'Could not decrypt key. Check the password and iterations number.';
            }
        }
    },
    template:`<div>
<div class="my-2 row"> 
    <div class="col-md-6">    
        <div>
            <label for="loadKeySelectedFile" class="form-label">Load from file</label>
            <input v-on:change="loadKeyFileSelected" class="form-control" type="file" id="loadKeySelectedFile" name="loadKeySelectedFile">
        </div>
    </div>
    <div class="col-md-6">
        <label class="form-label" for="loadKeyFrom">OR paste the key below</label>
        <div class="">
            <textarea v-model="loadKeyPastedText" name="loadKeyPastedText" id="loadKeyPastedText" class="form-control" style="height:1.15em;"></textarea>
        </div>
    </div>    
</div>
<div id="loadKeyFromHelp" class="form-text">Select key file or copy-paste into the above field</div>

<div class="my-2 row"> 
    <div class="col-md-6"> 
        <label class="form-label" for="loadKeyPassword">Password</label>
        <div class="input-group">                        
            <input v-model="loadKeyPassword" v-bind:type="loadKeyPasswordVisible?'text':'password'" class="form-control" id="loadKeyPassword" aria-describedby="loadKeyPasswordHelp" required="">
            <i class="input-group-text" id="loadKeyPasswordVisibleToggle" v-bind:class="{'bi bi-eye':loadKeyPasswordVisible, 'bi bi-eye-slash':!loadKeyPasswordVisible}" v-on:click="toggleLoadKeyPassword()"></i>
        </div>
        <div id="loadKeyPasswordHelp" class="form-text">The password entered while creating the key</div>
    </div>
    <div class="col-md-6"> 
        <label class="form-label" for="loadKeyIterations">Secret number</label>
        <input v-model.number="loadKeyIterations" type="number" min="600000" max="1000000" step="1000" class="form-control" id="loadKeyIterations" aria-describedby="loadKeyIterationsHelp" required="">
        <div id="loadKeyIterationsHelp" class="form-text">The number entered while creating the key</div>
    </div>
</div>     
<div class="my-2">
    <button type="button" v-on:click="loadKeySet()" class="btn btn-primary">Load key</button>
</div>
<div v-if="loadKeyError" class="alert alert-danger py-2">{{ loadKeyError }}</div>
</div>
`
};


const CreateNewKeysForm = {
    props:['keysCreatedCallback'],
    data() {
        return {
            newKeyName: '',
            newKeyPassword: '',
            newKeyIterations: 600000,
            newKeyPasswordVisible: false,
            newKeyInfo: null,
            newKeyError: null
        };              
    },
    methods: {
        toggleNewKeyPassword(){
            this.newKeyPasswordVisible = !this.newKeyPasswordVisible;
        },
        /**
         * create a new signing key and an encryption key, there will be separate keys for signing and encryption
         * 
         */
        async createNewKeySet(){
            this.newKeyError = null;
            if (!this.newKeyName.trim()) {
                this.newKeyError = 'Enter a key name.';
                return;
            }
            if (!this.newKeyPassword) {
                this.newKeyError = 'Enter a password.';
                return;
            }
            const iters = Number(this.newKeyIterations);
            if (!Number.isInteger(iters) || iters < 600000 || iters > 1000000) {
                this.newKeyError = 'Iterations must be a whole number between 600,000 and 1,000,000.';
                return;
            }
            let jwks = {
                public:{keys:[]},
                private:{keys:[]}
            };
            const pkcs1v15 = new SBO_RSASSAPKCS1v15();
            const signingKeys = await pkcs1v15.generateNewSigningKeyPair();
            if(signingKeys){
                jwks.private.keys.push(await SBO_CryptoUtils.exportCryptoKeyAsJwk(signingKeys.privateKey));
                jwks.public.keys.push(await SBO_CryptoUtils.exportCryptoKeyAsJwk(signingKeys.publicKey));
            }
            const rsaoaep = new SBO_RSAOAEP();
            const encKeys = await rsaoaep.generateKeyPair();
            if(encKeys){
                jwks.private.keys.push(await SBO_CryptoUtils.exportCryptoKeyAsJwk(encKeys.privateKey));
                jwks.public.keys.push(await SBO_CryptoUtils.exportCryptoKeyAsJwk(encKeys.publicKey));
            }

            const b64 = new SBO_Base64(false);

            let salt = SBO_CryptoUtils.getRandomBytes(16);
            let aesIv = SBO_CryptoUtils.getRandomBytes(12);

            const jwksString = JSON.stringify(jwks);


            let cryptoKeyForPbkdf = await SBO_PBKDF2.generateKey(this.newKeyPassword, salt, this.newKeyIterations, SBO_AES_ALG_NAME);
            let aesEnc = new SBO_AESEncrypt();
            const utf8encoder = new TextEncoder();
            let uint8ArrayFromPlainText = utf8encoder.encode(jwksString);

            let encResult = await aesEnc.encrypt(uint8ArrayFromPlainText, SBO_AES_ALG_NAME, cryptoKeyForPbkdf, aesIv);
            let nowSeconds = Math.round(Date.now() / 1000);
            this.newKeyInfo = {
                jwks: aesEnc.getCipherTextBase64Encoded(),
                salt: b64.encodeBytes(salt),
                iv: b64.encodeBytes(aesIv),
                name: this.newKeyName,
                created: nowSeconds
            };
            this.keysCreatedCallback(this.newKeyInfo, jwks);
        },        
    },
    template:`
<div>
<div class="my-2"> 
    <label class="form-label" for="newKeyName">Key name</label>
    <div class="input-group">                        
        <input v-model="newKeyName" type="text" class="form-control" id="newKeyName" aria-describedby="newKeyNameHelp" required="">                                    
    </div>
    <div id="newKeyNameHelp" class="form-text">A descriptive name for this key</div>
</div>
<div class="my-2"> 
    <label class="form-label" for="newKeyPassword">Password</label>
    <div class="input-group">                        
        <input v-model="newKeyPassword" v-bind:type="newKeyPasswordVisible?'text':'password'" class="form-control" id="newKeyPassword" aria-describedby="newKeyPasswordHelp" required="">
        <i class="input-group-text" id="newKeyPasswordVisibleToggle" v-bind:class="{'bi bi-eye':newKeyPasswordVisible, 'bi bi-eye-slash':!newKeyPasswordVisible}" v-on:click="toggleNewKeyPassword()"></i>
    </div>
    <div id="newKeyPasswordHelp" class="form-text">You will NOT be able to use/recover your key if you forget this password</div>
</div>
<div class="my-2">
    <label class="form-label" for="newKeyIterations">Iterations</label>
    <input v-model.number="newKeyIterations" type="number" min="600000" max="1000000" step="1000" class="form-control" id="newKeyIterations" aria-describedby="newKeyIterationsHelp">
    <div id="newKeyIterationsHelp" class="form-text">You will NOT be able to use/recover your key if you forget this number.</div>
</div>
<div class="my-2">
    <button type="button" v-on:click="createNewKeySet()" class="btn btn-primary">Create new key set</button>
</div>
<div v-if="newKeyError" class="alert alert-danger py-2">{{ newKeyError }}</div>
<div v-if="newKeyInfo">
    <div class="my-2"> 
        <div class="alert alert-light">
            <ul>    
            <li>Generated new keys successfully. </li>
            <li>You <b>MUST</b> save the keys now otherwise they will be lost when you close this page </li>
            <li>You will need the password and number you configured above to load these keys later. </li>
            </ul>
            <sbo-down-item file-name="SBOsecure-keyset.json" mime-type="application/octet-stream" v-bind:item-data="JSON.stringify(newKeyInfo)" data-type="keyset"></sbo-down-item>
        </div>
    </div>
</div>
</div>    
    `
    
};

const ContactInfo = {
    props:['contact', 'contactIndex', 'editContactCb', 'deleteContactCb'],
    data() {
        return {
        };              
    },
    methods: {
        printCreated() {
            return SBO_FormatTimestampSeconds(this.contact.created);
        },
        editContact(){
            this.editContactCb(this.contact, this.contactIndex);
        },
        deleteContact(){
            this.deleteContactCb(this.contactIndex);
        }
    },
    template:`<div>
<div class="row">
    <div class="col-auto flex-fill fw-medium">{{ contact.name }}</div>
    <div class="col-auto">
        <button type="button" v-on:click="editContact()" class="btn btn-sm btn-outline-light">
            <img src="img/pencil.svg" border="0">
        </button>

        <button type="button" v-on:click="deleteContact()" class="btn btn-sm btn-outline-light">
            <img src="img/trash.svg" border="0">
        </button>
    </div>
</div>
    <div>{{ printCreated() }} {{ contact.notes }}</div>
    <div>{{ contact.verifier }}</div>
</div>`
};
    
/**
 * Decrypts a package produced by EncryptForm.
 * Tries every loaded key against every recipient slot until one works.
 * Verifies the signature when present.
 */
const DecryptForm = {
    props: ['myKeys'],
    emits: ['encrypt-with-text'],
    data() {
        return {
            inputMode: 'paste',
            packageJson: '',
            selectedFile: null,
            decrypting: false,
            decryptError: null,
            decryptedText: null,
            decryptedBuffer: null,
            decryptedFileName: null,
            decryptedContentType: null,
            signatureStatus: null   // null | 'valid' | 'invalid' | 'unsigned' | 'error'
        };
    },
    computed: {
        parsedPackage() {
            if (!this.packageJson.trim()) return null;
            try {
                const p = JSON.parse(this.packageJson);
                return p && p.type === 'sbo-encrypted' ? p : null;
            } catch {
                return null;
            }
        },
        jsonError() {
            if (!this.packageJson.trim()) return null;
            try { JSON.parse(this.packageJson); return null; }
            catch { return 'Not valid JSON.'; }
        },
        packageInfo() {
            const p = this.parsedPackage;
            if (!p) return null;
            return {
                recipients: (p.encryptedKeys || []).map(k => k.recipientName).join(', '),
                originalName: p.encryptedContent && p.encryptedContent.originalName,
                signed: !!p.signerPublicKey
            };
        },
        canDecrypt() {
            return !!this.parsedPackage &&
                   this.myKeys && this.myKeys.length > 0 &&
                   !this.decrypting;
        }
    },
    methods: {
        onFileSelected(event) {
            const file = event.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                this.packageJson = e.target.result;
                this.resetResult();
            };
            reader.readAsText(file);
        },
        resetResult() {
            this.decryptError = null;
            this.decryptedText = null;
            this.decryptedBuffer = null;
            this.decryptedFileName = null;
            this.decryptedContentType = null;
            this.signatureStatus = null;
        },
        async decrypt() {
            this.resetResult();
            this.decrypting = true;
            try {
                const pkg = this.parsedPackage;
                if (!pkg) throw new Error('Paste or load a valid SBOsecure encrypted package first.');
                if (!pkg.encryptedKeys || pkg.encryptedKeys.length === 0) throw new Error('Package contains no recipient keys.');
                if (!this.myKeys || this.myKeys.length === 0) throw new Error('No keys loaded. Load your key in the Keys tab first.');

                // Try every (myKey × encryptedKey) combination until one decrypts
                const b64 = new SBO_Base64(false);
                const rsa = new SBO_RSAOAEP();
                let rawCek = null;

                outer:
                for (const myKey of this.myKeys) {
                    const decPrivJwk = myKey.jwks.private.keys.find(
                        k => k.key_ops && k.key_ops.includes('decrypt')
                    );
                    if (!decPrivJwk) continue;
                    const privKey = await rsa.importJwkPrivateKey(decPrivJwk);
                    for (const keyEntry of pkg.encryptedKeys) {
                        try {
                            const wrapped = b64.decodeAsByteArray(keyEntry.encryptedKey);
                            rawCek = await rsa.decrypt(privKey, wrapped);
                            break outer;
                        } catch { /* not this key, keep trying */ }
                    }
                }

                if (!rawCek) {
                    throw new Error(
                        'None of your loaded keys can decrypt this package. ' +
                        'You are not among the recipients, or the wrong key is loaded.'
                    );
                }

                // Import raw CEK and decrypt content
                const cek = await window.crypto.subtle.importKey(
                    'raw', rawCek, { name: SBO_AES_ALG_NAME }, false, ['decrypt']
                );

                const contentType = pkg.encryptedContent.contentType || 'text/plain';
                const isBinary = contentType !== 'text/plain';

                if (isBinary) {
                    const buf = await SBO_AESDecrypt.decryptAsBuffer(
                        pkg.encryptedContent.ciphertext,
                        pkg.encryptedContent.iv,
                        cek,
                        SBO_AES_ALG_NAME
                    );
                    if (buf === null) throw new Error('Decryption produced no output. The package may be corrupted.');
                    this.decryptedBuffer = buf;
                    this.decryptedContentType = contentType;
                } else {
                    const decrypted = await SBO_AESDecrypt.decrypt(
                        pkg.encryptedContent.ciphertext,
                        pkg.encryptedContent.iv,
                        cek,
                        SBO_AES_ALG_NAME
                    );
                    if (decrypted === null) throw new Error('Decryption produced no output. The package may be corrupted.');
                    this.decryptedText = decrypted;
                }
                this.decryptedFileName = pkg.encryptedContent.originalName || (isBinary ? 'decrypted-file' : 'decrypted.txt');

                // Verify signature
                if (!pkg.signature || !pkg.signerPublicKey) {
                    this.signatureStatus = 'unsigned';
                } else {
                    try {
                        const payload = {
                            version: pkg.version,
                            type: pkg.type,
                            encryptedContent: pkg.encryptedContent,
                            encryptedKeys: pkg.encryptedKeys
                        };
                        const pkcs = new SBO_RSASSAPKCS1v15();
                        const verifyKey = await pkcs.importVerificationPublicKey(pkg.signerPublicKey);
                        const sigBytes = b64.decodeAsByteArray(pkg.signature);
                        const valid = await pkcs.verifySignature(verifyKey, sigBytes, JSON.stringify(payload));
                        this.signatureStatus = valid ? 'valid' : 'invalid';
                    } catch {
                        this.signatureStatus = 'error';
                    }
                }

            } catch (err) {
                console.error('Decryption failed:', err);
                this.decryptError = err.message || 'Decryption failed.';
            } finally {
                this.decrypting = false;
            }
        },
        downloadDecrypted() {
            if (this.decryptedBuffer !== null) {
                SBO_SaveAsFile(new Uint8Array(this.decryptedBuffer), this.decryptedFileName, this.decryptedContentType || 'application/octet-stream');
            } else {
                SBO_SaveAsFile(this.decryptedText, this.decryptedFileName, 'application/octet-stream');
            }
        },
        reset() {
            this.inputMode = 'paste';
            this.packageJson = '';
            this.selectedFile = null;
            this.resetResult();
        },
        encryptDecryptedText() {
            this.$emit('encrypt-with-text', this.decryptedText);
        }
    },
    template: `<div>

<div class="my-2">
    <div class="btn-group" role="group" aria-label="Input type">
        <button type="button" class="btn btn-sm"
            v-bind:class="inputMode==='paste' ? 'btn-primary' : 'btn-outline-secondary'"
            v-on:click="inputMode='paste'">Paste</button>
        <button type="button" class="btn btn-sm"
            v-bind:class="inputMode==='file' ? 'btn-primary' : 'btn-outline-secondary'"
            v-on:click="inputMode='file'">Load file</button>
    </div>
</div>

<div v-if="inputMode==='paste'" class="my-2">
    <label class="form-label">Encrypted package (JSON)</label>
    <textarea v-model="packageJson" class="form-control font-monospace small" rows="6"
        placeholder="Paste the contents of a .sbo.json file here..."></textarea>
    <div v-if="jsonError" class="form-text text-danger">{{ jsonError }}</div>
</div>

<div v-if="inputMode==='file'" class="my-2">
    <label class="form-label">Load encrypted file</label>
    <input type="file" accept=".json" class="form-control" v-on:change="onFileSelected">
</div>

<div v-if="packageInfo" class="my-2 p-2 border rounded small text-secondary">
    <div v-if="packageInfo.recipients"><strong>For:</strong> {{ packageInfo.recipients }}</div>
    <div v-if="packageInfo.originalName"><strong>Original file:</strong> {{ packageInfo.originalName }}</div>
    <div>
        <strong>Signature:</strong>
        <span v-if="packageInfo.signed">Present</span>
        <span v-else class="text-warning">None — authenticity cannot be verified</span>
    </div>
</div>

<div v-if="!myKeys || myKeys.length === 0" class="alert alert-warning small p-2 my-2">
    No keys loaded. Load your keys in the Keys tab first.
</div>

<div class="my-2 d-flex gap-2 align-items-center flex-wrap">
    <button type="button" class="btn btn-primary" v-on:click="decrypt" v-bind:disabled="!canDecrypt">
        <span v-if="decrypting">Decrypting...</span>
        <span v-else>Decrypt</span>
    </button>
    <button type="button" class="btn btn-outline-secondary btn-sm" v-on:click="reset">
        <i class="bi bi-arrow-counterclockwise me-1"></i>Reset
    </button>
</div>

<div v-if="decryptError" class="alert alert-danger mt-2">
    <strong>Could not decrypt</strong><br>{{ decryptError }}
</div>

<div v-if="decryptedText !== null || decryptedBuffer !== null" class="my-2">
    <div class="mb-2">
        <span v-if="signatureStatus === 'valid'"   class="badge bg-success">Signature valid</span>
        <span v-if="signatureStatus === 'invalid'" class="badge bg-danger">Signature invalid — content may have been tampered</span>
        <span v-if="signatureStatus === 'error'"   class="badge bg-warning text-dark">Signature could not be verified</span>
        <span v-if="signatureStatus === 'unsigned'" class="badge bg-secondary">No signature</span>
    </div>
    <div v-if="decryptedBuffer !== null" class="alert alert-success d-flex align-items-center gap-3 flex-wrap">
        <i class="bi bi-check-circle-fill fs-5"></i>
        <div class="flex-fill">Binary file decrypted successfully.</div>
        <button type="button" class="btn btn-success btn-sm" v-on:click="downloadDecrypted">
            <img src="img/download.svg" border="0"> Save {{ decryptedFileName }}
        </button>
    </div>
    <div v-if="decryptedText !== null">
        <label class="form-label">Decrypted content</label>
        <textarea class="form-control font-monospace small" rows="10" v-model="decryptedText"></textarea>
        <div class="mt-2 d-flex gap-2 flex-wrap">
            <button type="button" class="btn btn-sm btn-outline-secondary" v-on:click="downloadDecrypted">
                <img src="img/download.svg" border="0"> Save as {{ decryptedFileName }}
            </button>
            <button type="button" class="btn btn-sm btn-warning" v-on:click="encryptDecryptedText">
                <i class="bi bi-lock-fill me-1"></i>Encrypt this text
            </button>
        </div>
    </div>
</div>

</div>`
};

/**
 * Encrypts a file or text message for one or more recipients using:
 * - AES-GCM for content encryption (authenticated encryption)
 * - RSA-OAEP to wrap the AES key per recipient
 * - RSASSA-PKCS1-v1_5 to sign the whole package with the user's own key
 */
const EncryptForm = {
    props: ['myKeys', 'myContacts', 'encryptPreload'],
    data() {
        return {
            inputMode: 'text',
            plainText: '',
            selectedFile: null,
            selectedFileName: '',
            selectedRecipients: [],
            encrypting: false,
            encryptError: null,
            encryptedPackageJson: null,
            encryptedFileName: null
        };
    },
    computed: {
        contactsWithKeys() {
            if (!this.myContacts) return [];
            return this.myContacts
                .map((c, i) => ({ contact: c, index: i }))
                .filter(({ contact }) => contact && contact.jwks);
        },
        canEncrypt() {
            const hasContent = this.inputMode === 'text'
                ? !!this.plainText.trim()
                : !!this.selectedFile;
            return hasContent && this.selectedRecipients.length > 0 && !this.encrypting;
        },
        hasShareApi() {
            return typeof navigator.share === 'function';
        }
    },
    watch: {
        encryptPreload(val) {
            if (val && val.text != null) {
                this.reset();
                this.inputMode = 'text';
                this.plainText = val.text;
            }
        }
    },
    methods: {
        reset() {
            this.inputMode = 'text';
            this.plainText = '';
            this.selectedFile = null;
            this.selectedFileName = '';
            this.selectedRecipients = [];
            this.encryptError = null;
            this.encryptedPackageJson = null;
            this.encryptedFileName = null;
        },
        onFileSelected(event) {
            const file = event.target.files[0];
            if (file) {
                this.selectedFile = file;
                this.selectedFileName = file.name;
            }
        },
        toggleRecipient(index) {
            const pos = this.selectedRecipients.indexOf(index);
            if (pos > -1) {
                this.selectedRecipients.splice(pos, 1);
            } else {
                this.selectedRecipients.push(index);
            }
        },
        async encrypt() {
            this.encryptError = null;
            this.encryptedPackageJson = null;
            this.encrypting = true;
            try {
                // 1. Read input as bytes
                let contentBytes;
                let originalName;
                let contentType;
                if (this.inputMode === 'file' && this.selectedFile) {
                    contentBytes = await this.selectedFile.arrayBuffer();
                    originalName = this.selectedFile.name;
                    contentType = this.selectedFile.type || 'application/octet-stream';
                } else {
                    contentBytes = new TextEncoder().encode(this.plainText);
                    originalName = 'message.txt';
                    contentType = 'text/plain';
                }

                // 2. Generate a random AES-GCM content encryption key (CEK)
                const aesKey = await window.crypto.subtle.generateKey(
                    { name: SBO_AES_ALG_NAME, length: 256 },
                    true,
                    ['encrypt', 'decrypt']
                );

                // 3. Encrypt content with the CEK
                const aesEnc = new SBO_AESEncrypt();
                await aesEnc.encrypt(contentBytes, SBO_AES_ALG_NAME, aesKey);

                // 4. Export raw CEK bytes so we can wrap it with RSA
                const rawAesKeyBuffer = await window.crypto.subtle.exportKey('raw', aesKey);

                // 5. Wrap the CEK with each recipient's RSA-OAEP public key
                const b64 = new SBO_Base64(false);
                const rsaoaep = new SBO_RSAOAEP();
                const encryptedKeys = [];

                for (const contactIndex of this.selectedRecipients) {
                    const contact = this.myContacts[contactIndex];
                    let contactJwks;
                    try {
                        contactJwks = JSON.parse(contact.jwks);
                    } catch (e) {
                        throw new Error(`Invalid key data for contact "${contact.name}"`);
                    }
                    const encKeyJwk = contactJwks.keys.find(
                        k => k.key_ops && k.key_ops.includes('encrypt')
                    );
                    if (!encKeyJwk) {
                        throw new Error(`No encryption key found for contact "${contact.name}"`);
                    }
                    const recipientPubKey = await rsaoaep.importJwkPublicKey(encKeyJwk);
                    const wrappedKeyBuffer = await rsaoaep.encrypt(recipientPubKey, rawAesKeyBuffer);
                    encryptedKeys.push({
                        recipientName: contact.name,
                        encryptedKey: b64.encodeBytes(new Uint8Array(wrappedKeyBuffer))
                    });
                }

                // 6. Assemble the payload that will be signed
                const payload = {
                    version: 1,
                    type: 'sbo-encrypted',
                    encryptedContent: {
                        ciphertext: aesEnc.getCipherTextBase64Encoded(),
                        iv: aesEnc.getIVBase64Encoded(),
                        originalName: originalName,
                        contentType: contentType
                    },
                    encryptedKeys: encryptedKeys
                };
                const payloadString = JSON.stringify(payload);

                // 7. Sign the payload with the user's RSASSA-PKCS1-v1_5 signing key
                let signature = null;
                let signerPublicKey = null;
                if (this.myKeys && this.myKeys.length > 0) {
                    const myKey = this.myKeys[0];
                    const signingPrivJwk = myKey.jwks.private.keys.find(
                        k => k.key_ops && k.key_ops.includes('sign')
                    );
                    if (signingPrivJwk) {
                        const pkcs1v15 = new SBO_RSASSAPKCS1v15();
                        const signingKey = await pkcs1v15.importSigningPrivateKey(signingPrivJwk);
                        const sigBuffer = await pkcs1v15.sign(signingKey, payloadString);
                        signature = b64.encodeBytes(new Uint8Array(sigBuffer));
                        signerPublicKey = myKey.jwks.public.keys.find(
                            k => k.key_ops && k.key_ops.includes('verify')
                        ) || null;
                    }
                }

                // 8. Produce the final package
                const finalPackage = Object.assign({}, payload, {
                    signature: signature,
                    signerPublicKey: signerPublicKey
                });
                this.encryptedPackageJson = JSON.stringify(finalPackage);
                this.encryptedFileName = originalName + '.sbo.json';

            } catch (err) {
                console.error('Encryption failed:', err);
                this.encryptError = err.message || 'Encryption failed';
            } finally {
                this.encrypting = false;
            }
        },
        download() {
            SBO_SaveAsFile(this.encryptedPackageJson, this.encryptedFileName, 'application/json');
        },
        async share() {
            const file = new File(
                [this.encryptedPackageJson],
                this.encryptedFileName,
                { type: 'application/json' }
            );
            try {
                if (navigator.canShare && navigator.canShare({ files: [file] })) {
                    await navigator.share({ files: [file], title: this.encryptedFileName });
                } else {
                    // File sharing not supported — share as text
                    await navigator.share({ title: this.encryptedFileName, text: this.encryptedPackageJson });
                }
            } catch (err) {
                // User cancelled or share failed — silently ignore cancellation
                if (err.name !== 'AbortError') {
                    console.error('Share failed:', err);
                }
            }
        }
    },
    template: `<div>
<div class="my-2">
    <div class="btn-group" role="group" aria-label="Input type">
        <button type="button" class="btn btn-sm"
            v-bind:class="inputMode==='text' ? 'btn-primary' : 'btn-outline-secondary'"
            v-on:click="inputMode='text'">Text</button>
        <button type="button" class="btn btn-sm"
            v-bind:class="inputMode==='file' ? 'btn-primary' : 'btn-outline-secondary'"
            v-on:click="inputMode='file'">File</button>
    </div>
</div>

<div v-if="inputMode==='text'" class="my-2">
    <label class="form-label">Message</label>
    <textarea v-model="plainText" class="form-control" rows="5" placeholder="Enter text to encrypt"></textarea>
</div>

<div v-if="inputMode==='file'" class="my-2">
    <label class="form-label">Select file</label>
    <input type="file" class="form-control" v-on:change="onFileSelected">
    <div v-if="selectedFileName" class="form-text">Selected: {{ selectedFileName }}</div>
</div>

<div class="my-2">
    <label class="form-label fw-medium">Recipients</label>
    <div v-if="contactsWithKeys.length === 0" class="text-secondary small">
        No contacts with keys. Add contacts with public keys in the Contacts tab.
    </div>
    <div v-for="item in contactsWithKeys" v-bind:key="item.index" class="form-check">
        <input class="form-check-input" type="checkbox"
            v-bind:id="'recipient-' + item.index"
            v-bind:checked="selectedRecipients.includes(item.index)"
            v-on:change="toggleRecipient(item.index)">
        <label class="form-check-label" v-bind:for="'recipient-' + item.index">
            {{ item.contact.name }}
        </label>
    </div>
</div>

<div class="my-2">
    <div v-if="!myKeys || myKeys.length === 0" class="alert alert-warning small p-2 mb-0">
        No keys loaded — package will not be signed. Load your keys in the Keys tab.
    </div>
    <div v-else class="text-secondary small">
        Signed with: {{ myKeys[0].downloadable.name }}
    </div>
</div>

<div class="my-2 d-flex gap-2 align-items-center flex-wrap">
    <button type="button" class="btn btn-warning" v-on:click="encrypt" v-bind:disabled="!canEncrypt">
        <span v-if="encrypting">Encrypting...</span>
        <span v-else>Encrypt</span>
    </button>
    <button type="button" class="btn btn-outline-secondary btn-sm" v-on:click="reset">
        <i class="bi bi-arrow-counterclockwise me-1"></i>Reset
    </button>
</div>

<div v-if="encryptError" class="alert alert-danger mt-2">{{ encryptError }}</div>

<div v-if="encryptedPackageJson" class="my-2">
    <div class="alert alert-success p-2 mb-2">Encryption successful!</div>
    <div class="d-flex gap-2 align-items-center">
        <button type="button" class="btn btn-primary" v-on:click="download">
            <img src="img/download.svg" border="0"> Download
        </button>
        <button v-if="hasShareApi" type="button" class="btn btn-secondary" v-on:click="share">Share</button>
    </div>
</div>
</div>`
};

const ContactForm = {
    props:['contact', 'contactIndex', 'saveContactCallback'],
    data() {
        return {
            contactInfo: {...this.contact},
            loadError: null
        };
    },
    methods: {
        printCreated() {
            if(this.contact){
                return SBO_FormatTimestampSeconds(this.contactInfo.created);
            }
            return '';
        },
        saveContact(){
            this.saveContactCallback(this.contactInfo, this.contactIndex);
        },
        cancelEdit(){
            this.saveContactCallback(null);
        },
        /**
         * Accepts either:
         *  - a public key set file  { keys: [...] }  (public.jwks.json from this app)
         *  - a single contact file  { name, notes, jwks, ... }
         * In the first case the jwks textarea is filled; in the second all fields are.
         */
        loadKeyFileSelected(event){
            this.loadError = null;
            const file = event.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const parsed = JSON.parse(e.target.result);
                    if (Array.isArray(parsed.keys)) {
                        // It's a public.jwks.json — populate the keys field only
                        this.contactInfo.jwks = e.target.result;
                    } else if (parsed.name !== undefined || parsed.jwks !== undefined) {
                        // It's a saved contact file — populate all fields
                        Object.assign(this.contactInfo, parsed);
                    } else {
                        this.loadError = 'Unrecognised file format.';
                    }
                } catch {
                    this.loadError = 'Could not parse file as JSON.';
                }
                event.target.value = '';
            };
            reader.readAsText(file);
        },
    },
    template:`<div>
<fieldset class="border border-primary-subtle rounded p-2">
    <legend class="fs-6">Load keys from file</legend>
    <div class="form-text mb-1">Load a <strong>public.jwks.json</strong> downloaded from SBOsecure, or a previously saved contact file.</div>
    <input class="form-control" type="file" accept=".json" v-on:change="loadKeyFileSelected">
    <div v-if="loadError" class="form-text text-danger">{{ loadError }}</div>
</fieldset>

<fieldset class="mt-2 rounded border border-primary-subtle p-2">
<legend class="fs-6">Contact details</legend>
    <div class="mb-2"><label class="form-label mb-0">Name</label><input class="form-control" type="text" v-model="contactInfo.name"></div>
    <div class="mb-2"><label class="form-label mb-0">Notes</label><textarea class="form-control" v-model="contactInfo.notes"></textarea></div>
    <div class="mb-2">
        <label class="form-label mb-0">Public keys</label>
        <div class="form-text mb-1">Paste the contents of <strong>public.jwks.json</strong> here, or load it from file above.</div>
        <textarea class="form-control form-control-sm font-monospace" rows="3" v-model="contactInfo.jwks" placeholder="{&quot;keys&quot;:[...]}"></textarea>
    </div>
    <div class="mb-2 text-center">
        <button type="button" v-on:click="cancelEdit" class="btn btn-sm btn-secondary me-2">Cancel</button>
        <button type="button" v-on:click="saveContact" class="btn btn-sm btn-primary"
            v-bind:disabled="!contactInfo.name || !contactInfo.jwks">Done</button>
    </div>
</fieldset>
</div>`
};