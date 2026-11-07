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
    // allowQr: also offer a "QR code" button. Never set it for private data such as keysets.
    props: ['fileName', 'mimeType', 'itemData', 'dataType', 'allowQr'],
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
    <sbo-qr-button v-if="allowQr" v-bind:item-data="itemData" v-bind:title="fileName"></sbo-qr-button>
</div>`
};


let SBO_QrButtonCounter = 0;

/**
 * Button that shows data as one or more QR codes in a modal.
 * Data above SBO_QR.MAX_DISPLAY_BYTES is not encoded; the modal says why.
 * Only use it for data that is safe to show on screen (public keys, encrypted packages).
 */
const QrDisplayButton = {
    // label: button text; pass "" for an icon-only button. btnClass: classes of the button.
    props: ['itemData', 'title', 'btnClass', 'label'],
    data() {
        return {
            uid: 'sboQr' + (++SBO_QrButtonCounter),
            open: false,
            codes: [],          // [{ qr, url }] one entry per part
            error: null,
            view: 'grid',       // 'grid' | 'single'
            current: 0,
            playTimer: null
        };
    },
    computed: {
        sizeKb() {
            return (SBO_QR.encodedLength(this.itemData || '') / 1024).toFixed(1);
        },
        buttonLabel() {
            return this.label !== undefined ? this.label : 'QR code';
        }
    },
    beforeUnmount() {
        this.stopPlaying();
        if (this.$refs.modal) {
            const modal = bootstrap.Modal.getInstance(this.$refs.modal);
            if (modal) modal.dispose();
        }
    },
    methods: {
        /**
         * Opens the modal and generates the codes.
         */
        async show() {
            this.stopPlaying();
            this.error = null;
            this.codes = [];
            this.view = 'grid';
            this.current = 0;
            this.open = true;
            await this.$nextTick();
            const el = this.$refs.modal;
            el.addEventListener('hidden.bs.modal', this.onHidden, { once: true });
            bootstrap.Modal.getOrCreateInstance(el).show();

            try {
                if (!this.itemData) throw new Error('There is nothing to show.');
                if (!SBO_QR.canDisplay(this.itemData)) {
                    throw new Error(`This data is ${this.sizeKb} KB. QR codes are only offered up to ` +
                        `${SBO_QR.MAX_DISPLAY_BYTES / 1024} KB; use Download instead.`);
                }
                const parts = await SBO_QR.split(this.itemData);
                const codes = [];
                for (const part of parts) {
                    const qr = Vue.markRaw(SBO_QR.encode(part));   // large immutable object, keep it out of reactivity
                    codes.push({ qr: qr, url: SBO_QR.toSvgDataUrl(qr) });
                }
                this.codes = codes;
            } catch (err) {
                console.error('QR generation failed:', err);
                this.error = err.message || 'Could not create QR codes.';
            }
        },
        onHidden() {
            this.stopPlaying();
            const modal = bootstrap.Modal.getInstance(this.$refs.modal);
            if (modal) modal.dispose();
            this.open = false;
            this.codes = [];
        },
        showSingle(index) {
            this.view = 'single';
            this.current = index;
        },
        next() {
            this.current = (this.current + 1) % this.codes.length;
        },
        previous() {
            this.current = (this.current + this.codes.length - 1) % this.codes.length;
        },
        /**
         * Cycles through the codes so another device can scan them one after the other.
         */
        togglePlaying() {
            if (this.playTimer) {
                this.stopPlaying();
            } else {
                this.playTimer = setInterval(() => this.next(), 1500);
            }
        },
        stopPlaying() {
            if (this.playTimer) {
                clearInterval(this.playTimer);
                this.playTimer = null;
            }
        },
        /**
         * Saves one code as a PNG file.
         */
        async saveImage(index) {
            const blob = await SBO_QR.toPngBlob(this.codes[index].qr);
            const base = (this.title || 'sbosecure').replace(/[^\w.-]+/g, '_');
            SBO_SaveAsFile(blob, `${base}-qr-${index + 1}-of-${this.codes.length}.png`, 'image/png');
        }
    },
    template: `<span>
<button type="button" v-bind:class="btnClass || 'btn btn-sm btn-outline-light'" v-on:click="show"
    title="Show as QR code" aria-label="Show as QR code">
    <i class="bi bi-qr-code"></i><span v-if="buttonLabel"> {{ buttonLabel }}</span>
</button>

<Teleport to="body">
<div v-if="open" class="modal fade" ref="modal" tabindex="-1" v-bind:aria-labelledby="uid + 'Title'" aria-hidden="true">
<div class="modal-dialog modal-lg modal-dialog-scrollable">
<div class="modal-content">
    <div class="modal-header">
        <h5 class="modal-title" v-bind:id="uid + 'Title'">
            <i class="bi bi-qr-code me-1"></i>{{ title || 'QR code' }}
        </h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
    </div>
    <div class="modal-body">
        <div v-if="error" class="alert alert-warning mb-0">{{ error }}</div>
        <div v-else-if="codes.length === 0" class="text-secondary">Creating QR codes…</div>
        <template v-else>
            <div class="small text-secondary mb-2">
                <span v-if="codes.length === 1">Scan this code with SBOsecure on the other device.</span>
                <span v-else>{{ codes.length }} codes. Scan all of them with SBOsecure on the other device, in any order.</span>
                Anyone who can see or photograph these codes gets a copy of this data.
            </div>

            <div v-if="codes.length > 1" class="btn-group mb-3" role="group" aria-label="QR view">
                <button type="button" class="btn btn-sm"
                    v-bind:class="view==='grid' ? 'btn-primary' : 'btn-outline-secondary'"
                    v-on:click="view='grid'; stopPlaying()">All codes</button>
                <button type="button" class="btn btn-sm"
                    v-bind:class="view==='single' ? 'btn-primary' : 'btn-outline-secondary'"
                    v-on:click="view='single'">One at a time</button>
            </div>

            <div v-if="view==='grid'" class="row g-3">
                <div v-for="(code, i) in codes" v-bind:key="i"
                     v-bind:class="codes.length === 1 ? 'col-12' : 'col-sm-6'" class="text-center">
                    <img v-bind:src="code.url" class="sbo-qr-img" v-bind:class="{'sbo-qr-img-lg': codes.length === 1}"
                         v-bind:alt="'QR code ' + (i + 1) + ' of ' + codes.length"
                         style="cursor:zoom-in" v-on:click="showSingle(i)">
                    <div class="small mt-1">
                        <span v-if="codes.length > 1" class="me-2">{{ i + 1 }} of {{ codes.length }}</span>
                        <a href="#" v-on:click.prevent="saveImage(i)"><i class="bi bi-download me-1"></i>Save image</a>
                    </div>
                </div>
            </div>

            <div v-if="view==='single'" class="text-center">
                <img v-bind:src="codes[current].url" class="sbo-qr-img sbo-qr-img-lg"
                     v-bind:alt="'QR code ' + (current + 1) + ' of ' + codes.length">
                <div class="d-flex justify-content-center align-items-center gap-2 mt-2">
                    <button type="button" class="btn btn-sm btn-outline-secondary" v-on:click="stopPlaying(); previous()"
                        aria-label="Previous code"><i class="bi bi-chevron-left"></i></button>
                    <span class="small">{{ current + 1 }} of {{ codes.length }}</span>
                    <button type="button" class="btn btn-sm btn-outline-secondary" v-on:click="stopPlaying(); next()"
                        aria-label="Next code"><i class="bi bi-chevron-right"></i></button>
                    <button type="button" class="btn btn-sm btn-outline-secondary" v-on:click="togglePlaying">
                        <i class="bi" v-bind:class="playTimer ? 'bi-pause-fill' : 'bi-play-fill'"></i>
                        {{ playTimer ? 'Pause' : 'Play' }}
                    </button>
                    <a href="#" class="small ms-2" v-on:click.prevent="saveImage(current)">Save image</a>
                </div>
            </div>
        </template>
    </div>
    <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
    </div>
</div>
</div>
</div>
</Teleport>
</span>`
};


/**
 * Reads data from one or more QR codes, live from the camera or from image files.
 * Emits 'scanned' with the reassembled text once every part of a set has been read.
 * Everything happens in the browser; the camera is turned off as soon as it is not needed.
 */
const QrScanner = {
    props: ['hint'],
    emits: ['scanned'],
    data() {
        return {
            hasCamera: !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia),
            cameraOn: false,
            cameraStarting: false,
            mirrored: false,        // preview of a user-facing camera is mirrored, like a mirror
            readingImages: false,
            received: 0,
            total: 0,
            error: null,
            notice: null,           // informational message, e.g. why the camera stopped
            done: false
        };
    },
    created() {
        // Deliberately not reactive: a MediaStream, a timer and the parts collected so far
        this.assembler = new SBO_QRAssembler();
        this.stream = null;
        this.scanTimer = null;
        // Camera session number. Every start and stop increments it, so a scan loop or a late
        // getUserMedia result from an older session can tell it is stale and stop itself.
        this.session = 0;
    },
    mounted() {
        document.addEventListener('visibilitychange', this.onVisibilityChange);
        SBO_QR.retainWorker();
    },
    beforeUnmount() {
        document.removeEventListener('visibilitychange', this.onVisibilityChange);
        this.stopCamera();
        SBO_QR.releaseWorker();
    },
    methods: {
        /**
         * Asks for camera access and starts scanning frames.
         */
        async startCamera() {
            this.stopCamera();
            const session = ++this.session;
            this.error = null;
            this.notice = null;
            this.done = false;
            this.cameraStarting = true;
            try {
                // Ask for a high resolution: browsers often default to 640x480, which leaves too few
                // pixels per module for dense codes. "ideal" falls back gracefully on lesser cameras.
                const stream = await navigator.mediaDevices.getUserMedia({
                    video: {
                        facingMode: { ideal: 'environment' },
                        width: { ideal: 1920 },
                        height: { ideal: 1080 }
                    },
                    audio: false
                });
                // Stopped, restarted, closed or hidden while the permission prompt was open
                if (session !== this.session || document.hidden || !this.$refs.video || !this.isVisible()) {
                    for (const track of stream.getTracks()) track.stop();
                    return;
                }
                this.stream = stream;
                const settings = stream.getVideoTracks()[0].getSettings();
                // Laptop webcams often report no facingMode; anything not facing away is treated as a selfie camera
                this.mirrored = settings.facingMode !== 'environment';
                const video = this.$refs.video;
                video.srcObject = stream;
                await video.play();
                if (session !== this.session) return;
                this.cameraOn = true;
                this.scheduleScan(session);
            } catch (err) {
                if (session !== this.session) return;
                this.stopCamera();
                if (err && err.name === 'NotAllowedError') {
                    this.error = 'Camera access was denied. Allow it in your browser settings, or choose images instead.';
                } else if (err && err.name === 'NotFoundError') {
                    this.error = 'No camera was found. Choose images instead.';
                } else {
                    this.error = 'Could not start the camera.';
                }
            } finally {
                if (session === this.session) this.cameraStarting = false;
            }
        },
        stopCamera() {
            this.session++;
            this.cameraStarting = false;
            if (this.scanTimer) {
                clearTimeout(this.scanTimer);
                this.scanTimer = null;
            }
            if (this.stream) {
                for (const track of this.stream.getTracks()) track.stop();
                this.stream = null;
            }
            if (this.$refs.video) this.$refs.video.srcObject = null;
            this.cameraOn = false;
        },
        onVisibilityChange() {
            // Never leave the camera running in a background tab
            if (document.hidden && this.cameraOn) {
                this.stopCamera();
                this.notice = 'The camera was turned off because the page was hidden.';
            }
        },
        /**
         * True while the scanner is on screen. App tabs are hidden with v-show, which keeps the
         * component mounted; an element inside a display:none ancestor has no offsetParent.
         */
        isVisible() {
            return !!this.$el && this.$el.offsetParent !== null;
        },
        scheduleScan(session) {
            this.scanTimer = setTimeout(() => this.scanFrame(session), 200);
        },
        /**
         * Looks for codes in the current video frame, then schedules the next look.
         * Stops quietly if the camera session it belongs to has ended.
         */
        async scanFrame(session) {
            this.scanTimer = null;
            const video = this.$refs.video;
            if (session !== this.session || !this.cameraOn || !video) return;
            if (!this.isVisible()) {
                // The user switched to another app tab: never scan where nobody can see it
                this.stopCamera();
                this.notice = 'The camera was turned off because you left this screen.';
                return;
            }
            if (video.readyState >= 2 && video.videoWidth > 0) {
                try {
                    // Read frames at full resolution (up to 1080p): shrinking them loses the detail
                    // dense codes need. Scans are scheduled after each read, so slow reads self-throttle.
                    const texts = await SBO_QR.decodeSource(video, video.videoWidth, video.videoHeight,
                        { maxSize: 1920, thorough: false });
                    if (session !== this.session) return;
                    for (const text of texts) {
                        if (await this.accept(text)) return;
                    }
                } catch (err) {
                    if (session !== this.session) return;
                    this.error = err.message || 'Could not read from the camera.';
                }
            }
            if (session === this.session && this.cameraOn) this.scheduleScan(session);
        },
        /**
         * Reads codes from the chosen image files.
         */
        async onImagesSelected(event) {
            const files = event.target.files;
            this.error = null;
            this.done = false;
            this.readingImages = true;
            try {
                for (const file of files) {
                    let texts;
                    try {
                        const bitmap = await SBO_QR.loadImageBitmap(file, 2000);
                        try {
                            texts = await SBO_QR.decodeSource(bitmap, bitmap.width, bitmap.height,
                                { maxSize: 2000, thorough: true });
                        } finally {
                            bitmap.close();
                        }
                    } catch (err) {
                        this.error = (err && /too large/.test(err.message))
                            ? err.message
                            : `Could not read ${file.name} as an image.`;
                        continue;
                    }
                    if (texts.length === 0) {
                        this.error = `No QR code found in ${file.name}.`;
                        continue;
                    }
                    for (const text of texts) {
                        if (await this.accept(text)) return;
                    }
                }
            } finally {
                this.readingImages = false;
                event.target.value = '';
            }
        },
        /**
         * Adds one scanned code. Returns true once the set is complete and has been emitted.
         */
        async accept(text) {
            let status;
            try {
                status = this.assembler.add(text);
            } catch (err) {
                this.error = err.message;
                return false;
            }
            this.received = this.assembler.received;
            this.total = this.assembler.total || 1;
            if (status !== 'complete') {
                if (status === 'added') this.error = null;
                return false;
            }

            let result;
            try {
                result = await this.assembler.result();
            } catch (err) {
                // Parts did not fit together: discard them and keep scanning
                this.error = err.message;
                this.resetParts();
                return false;
            }
            this.resetParts();
            this.stopCamera();
            this.done = true;
            this.error = null;
            this.$emit('scanned', result);
            return true;
        },
        resetParts() {
            this.assembler.reset();
            this.received = 0;
            this.total = 0;
        },
        startOver() {
            this.resetParts();
            this.error = null;
            this.done = false;
        }
    },
    template: `<div class="sbo-qr-scanner">
    <div class="d-flex gap-2 flex-wrap align-items-center mb-2">
        <button v-if="hasCamera && !cameraOn" type="button" class="btn btn-sm btn-primary"
            v-on:click="startCamera" v-bind:disabled="cameraStarting">
            <i class="bi bi-camera me-1"></i>{{ cameraStarting ? 'Starting camera…' : 'Use camera' }}
        </button>
        <button v-if="cameraOn" type="button" class="btn btn-sm btn-outline-secondary" v-on:click="stopCamera">
            <i class="bi bi-camera-video-off me-1"></i>Stop camera
        </button>
        <label class="btn btn-sm btn-secondary mb-0">
            <i class="bi bi-image me-1"></i>Choose image(s)…
            <input type="file" accept="image/*" multiple class="d-none" v-on:change="onImagesSelected">
        </label>
        <button v-if="received > 0" type="button" class="btn btn-sm btn-link" v-on:click="startOver">Start over</button>
    </div>

    <video ref="video" v-show="cameraOn" class="sbo-qr-video" v-bind:class="{'sbo-qr-video-mirrored': mirrored}"
        playsinline muted></video>

    <div v-if="total > 1" class="form-text fw-medium">
        <i class="bi bi-hourglass-split me-1"></i>Read {{ received }} of {{ total }} codes. Scan the rest in any order.
    </div>
    <div v-if="readingImages" class="form-text">Reading images…</div>
    <div v-if="done" class="form-text text-success"><i class="bi bi-check-circle-fill me-1"></i>QR code read.</div>
    <div v-if="error" class="form-text text-danger">{{ error }}</div>
    <div v-if="notice && !cameraOn" class="form-text text-secondary">
        <i class="bi bi-info-circle me-1"></i>{{ notice }}
    </div>
    <div class="form-text">
        <span v-if="hint">{{ hint }} </span>
        Images and camera frames are processed on this device only. If an image holds several codes and
        only one is found, use one image per code.
    </div>
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
            pbkdfError: null,
            pbkdfScanning: false    // QR scanner shown on the decrypt screen
        };
    },
    methods:{
        togglePbkdfPassword(){
            this.pbkdfPasswordVisible = !this.pbkdfPasswordVisible;
        },
        goBack(){
            this.pbkdfMode = null;
            this.pbkdfScanning = false;
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
                this.applyPbkdfPackageText(e.target.result);
                event.target.value = '';
            };
            reader.readAsText(file);
        },
        /**
         * Loads a password-encrypted package from its JSON text (file or QR code).
         * Returns true on success; otherwise sets pbkdfLoadError.
         */
        applyPbkdfPackageText(text){
            this.pbkdfLoadError = null;
            try {
                const pkg = JSON.parse(text);
                if (pkg.type !== 'sbo-pbkdf-encrypted') {
                    this.pbkdfLoadError = 'Not a password-encrypted package. Use the Decrypt tab for public-key packages.';
                    return false;
                }
                this.pbkdfCipherText = pkg.encryptedContent.ciphertext;
                this.pbkdfIV        = pkg.encryptedContent.iv;
                this.pbkdfSalt      = pkg.pbkdf.salt;
                this.pbkdfPackage   = null;
                this.pbkdfPlainText = '';
                this.pbkdfDecryptFailed = false;
                return true;
            } catch {
                this.pbkdfLoadError = 'Could not read the package.';
                return false;
            }
        },
        onPbkdfPackageScanned(text){
            if (this.applyPbkdfPackageText(text)) {
                this.pbkdfScanning = false;
            }
        }
    },
    template: `<div>

<!-- ── Mode selector ──────────────────────────────────── -->
<div v-if="pbkdfMode === null" class="row g-3 mt-1">
    <div class="col-sm-6">
        <div class="border rounded p-4 text-center h-100" style="cursor:pointer"
             v-on:click="pbkdfMode = 'encrypt'">
            <i class="bi bi-lock-fill fs-1 text-warning-emphasis d-block mb-2"></i>
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
        <sbo-qr-button v-bind:item-data="pbkdfPackage" title="Password-encrypted message"
            btn-class="btn btn-outline-success btn-sm"></sbo-qr-button>
    </div>
</div>

<!-- ── Decrypt screen ─────────────────────────────────── -->
<div v-if="pbkdfMode === 'decrypt'">
    <a href="#" class="small text-secondary d-inline-block mb-3" v-on:click.prevent="goBack()">
        <i class="bi bi-arrow-left me-1"></i>Back
    </a>
    <div class="mb-3">
        <label class="form-label">Encrypted package file</label>
        <div class="d-flex gap-2 flex-wrap">
            <label class="btn btn-secondary flex-fill text-start mb-0" style="cursor:pointer">
                <i class="bi bi-folder2-open me-2"></i>Load encrypted package…
                <input type="file" accept=".json" class="d-none" v-on:change="loadPbkdfPackageFile">
            </label>
            <button type="button" class="btn"
                v-bind:class="pbkdfScanning ? 'btn-primary' : 'btn-outline-secondary'"
                v-on:click="pbkdfScanning = !pbkdfScanning">
                <i class="bi bi-qr-code-scan me-1"></i>Scan QR code
            </button>
        </div>
        <div v-if="pbkdfScanning" class="border rounded p-2 mt-2">
            <sbo-qr-scanner hint="Scan the QR code(s) of the password-encrypted message."
                v-on:scanned="onPbkdfPackageScanned"></sbo-qr-scanner>
        </div>
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
            <input v-on:change="loadKeyFileSelected" class="form-control" type="file" accept=".json" id="loadKeySelectedFile" name="loadKeySelectedFile">
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

/**
 * Returns a clean copy of a contact with only the known fields, or null if it is not a usable contact.
 * Contact data can come from files or QR codes made by anyone, so nothing else is copied and every
 * field must have the expected type.
 */
function SBO_SanitizeContact(c) {
    if (!c || typeof c !== 'object' || Array.isArray(c)) return null;
    const contact = {};
    if (typeof c.name === 'string') contact.name = c.name;
    if (typeof c.notes === 'string') contact.notes = c.notes;
    if (typeof c.jwks === 'string' && c.jwks) contact.jwks = c.jwks;
    if (typeof c.verifier === 'string') contact.verifier = c.verifier;
    if (Number.isFinite(c.created)) contact.created = c.created;
    if (!contact.name && !contact.jwks) return null;
    return contact;
}

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
        <sbo-qr-button v-if="contact.jwks" v-bind:item-data="contact.jwks" label=""
            v-bind:title="(contact.name || 'Contact') + ' public key'"></sbo-qr-button>

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
    props: ['myKeys', 'myContacts'],
    emits: ['encrypt-with-text'],
    data() {
        return {
            inputMode: 'paste',
            packageJson: '',
            selectedFile: null,
            decrypting: false,
            decryptError: null,
            noMatchingKey: false,   // true when decryption failed because no loaded key fits
            details: null,          // contents of the document details modal, see buildDetails()
            decryptedText: null,
            decryptedBuffer: null,
            decryptedFileName: null,
            decryptedContentType: null,
            signatureStatus: null,  // null | 'valid' | 'invalid' | 'unsigned' | 'error'
            signer: null            // who signed a valid package, see identifySigner()
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
        /**
         * Explains what the input is when it is valid JSON but not an encrypted package,
         * e.g. a public key scanned on the wrong screen. Null if there is nothing to explain.
         */
        packageKindError() {
            if (!this.packageJson.trim() || this.jsonError || this.parsedPackage) return null;
            let p;
            try {
                p = JSON.parse(this.packageJson);
            } catch {
                return null;
            }
            if (p && p.type === 'sbo-pbkdf-encrypted') {
                return 'This is a password-encrypted message. Open it in Password Enc. → Decrypt a message.';
            }
            if (p && Array.isArray(p.keys)) {
                return 'This is a public key, not an encrypted package. Add it as a contact in the Contacts tab.';
            }
            if (p && p.jwks && p.salt && p.iv) {
                return 'This is a keyset file. Load it in the My Keys tab.';
            }
            if (p && typeof p.jwks === 'string') {
                return 'This is a contact, not an encrypted package. Import it in the Contacts tab.';
            }
            return 'This is not an SBOsecure encrypted package.';
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
    watch: {
        // A different package makes the previous result and error meaningless
        packageJson() {
            this.resetResult();
        },
        // A "no matching key" failure is stale once the set of loaded keys changes; the user must retry
        'myKeys.length'() {
            if (this.noMatchingKey) {
                this.noMatchingKey = false;
                this.decryptError = null;
            }
            this.refreshSigner();
        },
        // Adding or editing a contact can change who a valid signature is attributed to
        myContacts: {
            deep: true,
            handler() {
                this.refreshSigner();
            }
        }
    },
    methods: {
        /**
         * Re-identifies the signer of the current valid package against the current keys and contacts.
         */
        async refreshSigner() {
            const pkg = this.parsedPackage;
            if (this.signatureStatus !== 'valid' || !pkg) return;
            this.signer = this.identifySigner(
                await this.safeThumbprint(pkg.signerPublicKey),
                await this.collectLoadedKeyFingerprints(),
                await this.collectContactFingerprints()
            );
        },
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
            this.noMatchingKey = false;
            this.decryptedText = null;
            this.decryptedBuffer = null;
            this.decryptedFileName = null;
            this.decryptedContentType = null;
            this.signatureStatus = null;
            this.signer = null;
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
                    this.noMatchingKey = true;
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
                    // The signing key travels inside the package, so anyone can produce a "valid" signature.
                    // Only a match with a known key tells the user who actually signed it.
                    await this.refreshSigner();
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
        /**
         * Takes a package read from QR codes and shows it in the paste box,
         * so it goes through the same checks as pasted text.
         */
        onPackageScanned(text) {
            this.packageJson = text;
            this.inputMode = 'paste';
        },
        encryptDecryptedText() {
            this.$emit('encrypt-with-text', this.decryptedText);
        },
        formatFingerprint(hex) {
            return SBO_CryptoUtils.formatFingerprint(hex);
        },
        /**
         * Fingerprint of a JWK, or null if the key is missing or malformed.
         */
        async safeThumbprint(jwk) {
            if (!jwk) return null;
            try {
                return await SBO_CryptoUtils.jwkThumbprint(jwk);
            } catch {
                return null;
            }
        },
        /**
         * Returns the first JWK in the list whose key_ops contains the given operation, or null.
         */
        findJwkByOp(keys, op) {
            if (!keys) return null;
            for (const k of keys) {
                if (k.key_ops && k.key_ops.includes(op)) return k;
            }
            return null;
        },
        /**
         * Fingerprints of the user's loaded keys (decryption and signing halves).
         */
        async collectLoadedKeyFingerprints() {
            const result = [];
            for (const myKey of (this.myKeys || [])) {
                const decJwk = this.findJwkByOp(myKey.jwks.private.keys, 'decrypt');
                const verifyJwk = this.findJwkByOp(myKey.jwks.public.keys, 'verify');
                result.push({
                    name: myKey.downloadable.name || '(unnamed key)',
                    created: SBO_FormatTimestampSeconds(myKey.downloadable.created),
                    encKeyId: await this.safeThumbprint(decJwk),
                    signKeyId: await this.safeThumbprint(verifyJwk)
                });
            }
            return result;
        },
        /**
         * Fingerprints of the public keys stored in the user's contacts.
         * Contacts with unparsable key data are skipped.
         */
        async collectContactFingerprints() {
            const result = [];
            for (const contact of (this.myContacts || [])) {
                if (!contact || !contact.jwks) continue;
                let jwks;
                try {
                    jwks = JSON.parse(contact.jwks);
                } catch {
                    continue;
                }
                const encJwk = this.findJwkByOp(jwks.keys, 'encrypt');
                const verifyJwk = this.findJwkByOp(jwks.keys, 'verify');
                result.push({
                    name: contact.name || '(unnamed contact)',
                    encKeyId: await this.safeThumbprint(encJwk),
                    signKeyId: await this.safeThumbprint(verifyJwk)
                });
            }
            return result;
        },
        /**
         * Returns the name of the first entry whose given fingerprint field equals keyId, or null.
         */
        findNameByKeyId(entries, field, keyId) {
            if (!keyId) return null;
            for (const e of entries) {
                if (e[field] === keyId) return e.name;
            }
            return null;
        },
        /**
         * Matches a signer key fingerprint against the loaded keys and contacts.
         * Returns { keyId, matchedKeyName, matchedContactName }; both names are null for an unknown signer.
         */
        identifySigner(signerKeyId, loadedKeys, contacts) {
            return {
                keyId: signerKeyId,
                matchedKeyName: this.findNameByKeyId(loadedKeys, 'signKeyId', signerKeyId),
                matchedContactName: this.findNameByKeyId(contacts, 'signKeyId', signerKeyId)
            };
        },
        /**
         * Compares what the package expects (recipient keys, signer) with the loaded keys
         * and contacts, and produces human readable hints about why decryption might fail.
         */
        async buildDetails() {
            const pkg = this.parsedPackage;
            if (!pkg) return null;

            const loadedKeys = await this.collectLoadedKeyFingerprints();
            const contacts = await this.collectContactFingerprints();

            // Recipients the package was encrypted for
            const recipients = [];
            let anyRecipientMatches = false;
            let legacyRecipients = 0;
            for (const entry of (pkg.encryptedKeys || [])) {
                const keyId = entry.keyId || null;
                if (!keyId) legacyRecipients++;
                const matchedKeyName = this.findNameByKeyId(loadedKeys, 'encKeyId', keyId);
                if (matchedKeyName) anyRecipientMatches = true;
                recipients.push({
                    name: entry.recipientName || '(unnamed)',
                    keyId: keyId,
                    matchedKeyName: matchedKeyName,
                    matchedContactName: this.findNameByKeyId(contacts, 'encKeyId', keyId)
                });
            }

            // Signer of the package
            let signer = null;
            if (pkg.signerPublicKey) {
                signer = this.identifySigner(
                    await this.safeThumbprint(pkg.signerPublicKey), loadedKeys, contacts
                );
            }

            const hints = this.buildHints(loadedKeys, recipients, signer, anyRecipientMatches, legacyRecipients);

            return {
                originalName: pkg.encryptedContent && pkg.encryptedContent.originalName,
                contentType: pkg.encryptedContent && pkg.encryptedContent.contentType,
                version: pkg.version,
                recipients: recipients,
                signer: signer,
                loadedKeys: loadedKeys,
                hints: hints
            };
        },
        /**
         * Builds the list of diagnostic hints shown at the top of the details modal.
         */
        buildHints(loadedKeys, recipients, signer, anyRecipientMatches, legacyRecipients) {
            const hints = [];
            if (loadedKeys.length === 0) {
                hints.push('No keys are loaded. Load your keyset in the Keys tab.');
                return hints;
            }
            if (recipients.length === 0) {
                hints.push('The package does not list any recipients.');
                return hints;
            }

            if (legacyRecipients > 0) {
                hints.push('This package was created with an older version of SBOsecure that does not record key ' +
                    'fingerprints, so only recipient names can be shown. Compare the recipient names with your key name.');
            }

            if (anyRecipientMatches) {
                if (this.noMatchingKey) {
                    hints.push('One of your loaded keys matches a recipient fingerprint, but the content key could not be ' +
                        'unwrapped. The package may be corrupted or modified.');
                }
                return hints;
            }

            if (legacyRecipients < recipients.length) {
                hints.push('None of the recipient key fingerprints match a key you have loaded.');
            }

            // Same name as one of our keys but different fingerprint: sender has a stale/different public key for us
            for (const r of recipients) {
                if (!r.keyId) continue;
                for (const lk of loadedKeys) {
                    if (r.name.trim().toLowerCase() === lk.name.trim().toLowerCase()) {
                        hints.push(`Recipient "${r.name}" has the same name as your key "${lk.name}" but a different ` +
                            'fingerprint. The sender probably has an old or different public key for you. Send them your ' +
                            'current public key (Keys tab) and ask them to encrypt again.');
                    }
                }
            }

            if (signer && signer.matchedKeyName) {
                hints.push(`This package was signed with your own key "${signer.matchedKeyName}", so you created it. ` +
                    'The sender of a package cannot decrypt it unless they also selected themselves as a recipient. ' +
                    'Add yourself to your contacts with your public key and encrypt again with yourself included.');
            }

            for (const r of recipients) {
                if (r.matchedContactName) {
                    hints.push(`The package was encrypted for your contact "${r.matchedContactName}". Only they can decrypt it.`);
                }
            }

            if (legacyRecipients < recipients.length) {
                hints.push('If you have more than one keyset, load the one whose fingerprint matches a recipient below. ' +
                    'Otherwise ask the sender to compare the fingerprint they have for you with your fingerprint listed under "Your loaded keys".');
            }
            return hints;
        },
        /**
         * Opens the document details modal and fills it in.
         */
        async showDetails() {
            this.details = null;
            bootstrap.Modal.getOrCreateInstance(this.$refs.detailsModal).show();
            try {
                const details = await this.buildDetails();
                this.details = details || { error: 'Paste or load a valid SBOsecure encrypted package first.' };
            } catch (err) {
                console.error('Could not build document details:', err);
                this.details = { error: 'Could not read the package details.' };
            }
        }
    },
    beforeUnmount() {
        const modal = bootstrap.Modal.getInstance(this.$refs.detailsModal);
        if (modal) modal.dispose();
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
        <button type="button" class="btn btn-sm"
            v-bind:class="inputMode==='qr' ? 'btn-primary' : 'btn-outline-secondary'"
            v-on:click="inputMode='qr'"><i class="bi bi-qr-code-scan me-1"></i>Scan QR</button>
    </div>
</div>

<div v-if="inputMode==='qr'" class="my-2">
    <sbo-qr-scanner hint="Scan the QR code(s) of the encrypted package."
        v-on:scanned="onPackageScanned"></sbo-qr-scanner>
</div>

<div v-if="inputMode==='paste'" class="my-2">
    <label class="form-label">Encrypted package (JSON)</label>
    <textarea v-model="packageJson" class="form-control font-monospace small" rows="6"
        placeholder="Paste the contents of a .sbo.json file here..."></textarea>
</div>

<div v-if="inputMode==='file'" class="my-2">
    <label class="form-label">Load encrypted file</label>
    <input type="file" accept=".json" class="form-control" v-on:change="onFileSelected">
</div>

<div v-if="jsonError || packageKindError" class="form-text text-danger mb-2">
    <i class="bi bi-exclamation-circle me-1"></i>{{ jsonError || packageKindError }}
</div>

<div v-if="packageInfo" class="my-2 p-2 border rounded small text-secondary">
    <div v-if="packageInfo.recipients"><strong>For:</strong> {{ packageInfo.recipients }}</div>
    <div v-if="packageInfo.originalName"><strong>Original file:</strong> {{ packageInfo.originalName }}</div>
    <div>
        <strong>Signature:</strong>
        <span v-if="packageInfo.signed">Present</span>
        <span v-else class="text-danger">None! Authenticity cannot be verified</span>
    </div>
    <a href="#" class="d-inline-block mt-1" v-on:click.prevent="showDetails">
        <i class="bi bi-info-circle me-1"></i>Show document details
    </a>
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
    <div v-if="noMatchingKey" class="mt-2">
        <a href="#" class="alert-link" v-on:click.prevent="showDetails">
            <i class="bi bi-search me-1"></i>Find out why — compare the keys this document expects with your loaded keys
        </a>
    </div>
</div>

<div v-if="decryptedText !== null || decryptedBuffer !== null" class="my-2">
    <div class="mb-2">
        <template v-if="signatureStatus === 'valid' && signer">
            <span v-if="signer.matchedContactName" class="badge bg-success">
                Signature valid — signed by contact "{{ signer.matchedContactName }}"
            </span>
            <span v-else-if="signer.matchedKeyName" class="badge bg-success">
                Signature valid — signed by you ("{{ signer.matchedKeyName }}")
            </span>
            <template v-else>
                <span class="badge bg-warning text-dark">Signature valid, but the signer is not in your contacts</span>
                <div class="form-text">
                    Anyone can sign a package, so this does not tell you who sent it.
                    Add the sender as a contact to confirm it came from them.
                    <a href="#" v-on:click.prevent="showDetails">Show signer fingerprint</a>
                </div>
            </template>
        </template>
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

<!-- ── Document details modal ─────────────────────────── -->
<Teleport to="body">
<div class="modal fade" ref="detailsModal" tabindex="-1" aria-labelledby="sboDocDetailsTitle" aria-hidden="true">
<div class="modal-dialog modal-lg modal-dialog-scrollable">
<div class="modal-content">
    <div class="modal-header">
        <h5 class="modal-title" id="sboDocDetailsTitle">Document details</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
    </div>
    <div class="modal-body small">
        <div v-if="!details" class="text-secondary">Reading package…</div>
        <div v-else-if="details.error" class="alert alert-danger">{{ details.error }}</div>
        <template v-else>

        <div v-if="details.hints.length > 0" class="alert alert-warning">
            <div class="fw-semibold mb-1"><i class="bi bi-lightbulb-fill me-1"></i>What might be wrong</div>
            <ul class="mb-0 ps-3">
                <li v-for="(hint, i) in details.hints" v-bind:key="i">{{ hint }}</li>
            </ul>
        </div>

        <h6 class="mt-3">Package</h6>
        <table class="table table-sm mb-3">
            <tbody>
                <tr><th class="w-25">Original name</th><td>{{ details.originalName || '—' }}</td></tr>
                <tr><th>Content type</th><td>{{ details.contentType || 'text/plain' }}</td></tr>
                <tr><th>Format version</th><td>{{ details.version }}</td></tr>
            </tbody>
        </table>

        <h6>Expected keys (recipients)</h6>
        <div class="text-secondary mb-1">A loaded key must match one of these fingerprints to decrypt.</div>
        <table class="table table-sm mb-3">
            <thead><tr><th>Recipient</th><th>Key fingerprint</th><th>Status</th></tr></thead>
            <tbody>
                <tr v-for="(r, i) in details.recipients" v-bind:key="i">
                    <td>{{ r.name }}</td>
                    <td class="font-monospace">
                        <span v-if="r.keyId">{{ formatFingerprint(r.keyId) }}</span>
                        <span v-else class="text-secondary">not recorded</span>
                    </td>
                    <td>
                        <span v-if="r.matchedKeyName" class="badge bg-success">Your key "{{ r.matchedKeyName }}"</span>
                        <span v-else-if="r.matchedContactName" class="badge bg-info text-dark">Contact "{{ r.matchedContactName }}"</span>
                        <span v-else-if="r.keyId" class="badge bg-danger">No loaded key matches</span>
                        <span v-else class="badge bg-secondary">Unknown</span>
                    </td>
                </tr>
            </tbody>
        </table>

        <h6>Signed by</h6>
        <div v-if="!details.signer" class="text-danger mb-3">The package is not signed.</div>
        <table v-else class="table table-sm mb-3">
            <tbody>
                <tr>
                    <th class="w-25">Key fingerprint</th>
                    <td class="font-monospace">{{ formatFingerprint(details.signer.keyId) || '—' }}</td>
                </tr>
                <tr>
                    <th>Signer</th>
                    <td>
                        <span v-if="details.signer.matchedKeyName" class="badge bg-primary">You ("{{ details.signer.matchedKeyName }}")</span>
                        <span v-else-if="details.signer.matchedContactName" class="badge bg-info text-dark">Contact "{{ details.signer.matchedContactName }}"</span>
                        <span v-else class="badge bg-secondary">Not one of your keys or contacts</span>
                    </td>
                </tr>
            </tbody>
        </table>

        <h6>Your loaded keys</h6>
        <div v-if="details.loadedKeys.length === 0" class="text-warning-emphasis">No keys loaded.</div>
        <table v-else class="table table-sm mb-0">
            <thead><tr><th>Name</th><th>Created</th><th>Decryption key fingerprint</th></tr></thead>
            <tbody>
                <tr v-for="(k, i) in details.loadedKeys" v-bind:key="i">
                    <td>{{ k.name }}</td>
                    <td>{{ k.created }}</td>
                    <td class="font-monospace">{{ formatFingerprint(k.encKeyId) || '—' }}</td>
                </tr>
            </tbody>
        </table>

        </template>
    </div>
    <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
    </div>
</div>
</div>
</div>
</Teleport>

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
                        // Fingerprint of the recipient's public key, lets the recipient see which key was expected
                        keyId: await SBO_CryptoUtils.jwkThumbprint(encKeyJwk),
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
    <input type="file" class="form-control" accept="*/*" v-on:change="onFileSelected">
    <div v-if="selectedFileName" class="form-text">Selected: {{ selectedFileName }}</div>
</div>

<div class="my-2">
    <label class="form-label fw-bold">Recipients</label>
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
        Encrypted package will be signed with: {{ myKeys[0].downloadable.name }}
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
        <sbo-qr-button v-bind:item-data="encryptedPackageJson" v-bind:title="encryptedFileName"
            btn-class="btn btn-secondary" label="Show QR code"></sbo-qr-button>
    </div>
</div>
</div>`
};

const ContactForm = {
    props:['contact', 'contactIndex', 'saveContactCallback'],
    data() {
        return {
            contactInfo: {...this.contact},
            // New contacts start with file loading; existing ones show their pasted keys
            keyInputMode: (this.contact && this.contact.jwks) ? 'paste' : 'file',
            loadedFileName: null,
            loadedJwks: null,       // the keys as loaded from loadedFileName, to detect later edits
            loadError: null,
            keyFingerprint: null,   // formatted fingerprint of the encryption key, for comparing with the contact
            keysUnreadable: false   // keys are set but contain no usable encryption key
        };
    },
    watch: {
        'contactInfo.jwks': {
            immediate: true,
            handler() {
                this.updateFingerprint();
            }
        }
    },
    computed: {
        /**
         * Name of the file the current keys came from, or null if no file was loaded
         * or the keys were edited afterwards.
         */
        keysLoadedFrom() {
            if (this.loadedFileName && this.contactInfo.jwks && this.contactInfo.jwks === this.loadedJwks) {
                return this.loadedFileName;
            }
            return null;
        }
    },
    methods: {
        /**
         * Remembers which file the current keys were loaded from.
         */
        markKeysLoaded(fileName) {
            this.loadedFileName = fileName;
            this.loadedJwks = this.contactInfo.jwks;
        },
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
         * Recomputes the fingerprint of the encryption key in the keys field.
         */
        async updateFingerprint() {
            const text = this.contactInfo.jwks;
            let fingerprint = null;
            let unreadable = false;
            if (text) {
                try {
                    const jwks = JSON.parse(text);
                    let encJwk = null;
                    for (const k of (jwks.keys || [])) {
                        if (k.key_ops && k.key_ops.includes('encrypt')) {
                            encJwk = k;
                            break;
                        }
                    }
                    fingerprint = SBO_CryptoUtils.formatFingerprint(await SBO_CryptoUtils.jwkThumbprint(encJwk));
                } catch {
                    unreadable = true;
                }
            }
            // Ignore the result if the keys changed while hashing
            if (text === this.contactInfo.jwks) {
                this.keyFingerprint = fingerprint;
                this.keysUnreadable = unreadable;
            }
        },
        /**
         * Applies key data from a file or QR code. Accepts either:
         *  - a public key set  { keys: [...] }  (public.jwks.json from this app)
         *  - a single contact  { name, notes, jwks, ... }
         * In the first case only the keys field is filled; in the second all fields are.
         * @param {string} text   the JSON text
         * @param {string} source shown to the user, e.g. the file name
         * @returns {boolean} true if keys were loaded
         */
        applyKeyText(text, source){
            this.loadError = null;
            this.loadedFileName = null;
            this.loadedJwks = null;
            let parsed;
            try {
                parsed = JSON.parse(text);
            } catch {
                this.loadError = 'Could not read the data as JSON.';
                return false;
            }
            if (parsed && Array.isArray(parsed.keys)) {
                this.contactInfo.jwks = text;
                this.markKeysLoaded(source);
                return true;
            }
            // The data may come from anyone (e.g. a scanned QR code): take only known, well-typed fields
            const contact = SBO_SanitizeContact(parsed);
            if (contact) {
                if (contact.name !== undefined) this.contactInfo.name = contact.name;
                if (contact.notes !== undefined) this.contactInfo.notes = contact.notes;
                if (contact.jwks) {
                    this.contactInfo.jwks = contact.jwks;
                    this.markKeysLoaded(source);
                    return true;
                }
                this.loadError = 'This contact has no public keys. Name and notes were filled in; ' +
                    'load or paste the public keys separately.';
                return false;
            }
            this.loadError = 'Unrecognised format. Expected a public.jwks.json or a saved contact.';
            return false;
        },
        loadKeyFileSelected(event){
            const file = event.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                this.applyKeyText(e.target.result, file.name);
                event.target.value = '';
            };
            reader.readAsText(file);
        },
        onKeysScanned(text){
            this.applyKeyText(text, 'QR code');
        },
    },
    template:`<div>
<fieldset class="rounded border border-primary-subtle p-2">
<legend class="fs-6">Contact details</legend>
    <div class="mb-2"><label class="form-label mb-0">Name</label><input class="form-control" type="text" v-model="contactInfo.name"></div>
    <div class="mb-2"><label class="form-label mb-0">Notes</label><textarea class="form-control" v-model="contactInfo.notes"></textarea></div>
    <div class="mb-2">
        <label class="form-label mb-1">Public keys</label>
        <div class="mb-2">
            <div class="btn-group" role="group" aria-label="Public key input">
                <button type="button" class="btn btn-sm"
                    v-bind:class="keyInputMode==='file' ? 'btn-primary' : 'btn-outline-secondary'"
                    v-on:click="keyInputMode='file'">Load file</button>
                <button type="button" class="btn btn-sm"
                    v-bind:class="keyInputMode==='paste' ? 'btn-primary' : 'btn-outline-secondary'"
                    v-on:click="keyInputMode='paste'">Paste</button>
                <button type="button" class="btn btn-sm"
                    v-bind:class="keyInputMode==='qr' ? 'btn-primary' : 'btn-outline-secondary'"
                    v-on:click="keyInputMode='qr'"><i class="bi bi-qr-code-scan me-1"></i>Scan QR</button>
            </div>
        </div>

        <div v-if="keyInputMode==='file'">
            <input class="form-control" type="file" accept=".json" v-on:change="loadKeyFileSelected">
            <div class="form-text">Select the <strong>public.jwks.json</strong> your contact gave you, or a previously saved contact file (this also fills in name and notes).</div>
        </div>

        <div v-if="keyInputMode==='paste'">
            <textarea class="form-control form-control-sm font-monospace" rows="3" v-model="contactInfo.jwks" placeholder="{&quot;keys&quot;:[...]}"></textarea>
            <div class="form-text">Paste the contents of <strong>public.jwks.json</strong>.</div>
        </div>

        <div v-if="keyInputMode==='qr'">
            <sbo-qr-scanner hint="Scan the public key QR code your contact shows you."
                v-on:scanned="onKeysScanned"></sbo-qr-scanner>
        </div>

        <template v-if="keyInputMode !== 'paste'">
            <div v-if="keysLoadedFrom" class="form-text text-success">
                <i class="bi bi-check-circle-fill me-1"></i>Keys loaded from {{ keysLoadedFrom }}
            </div>
            <div v-else-if="contactInfo.jwks" class="form-text text-secondary">
                <i class="bi bi-key me-1"></i>Keys already set. Loading new ones replaces them.
            </div>
        </template>

        <div v-if="loadError" class="form-text text-danger">{{ loadError }}</div>

        <div v-if="keyFingerprint" class="form-text">
            <i class="bi bi-fingerprint me-1"></i>Encryption key fingerprint:
            <span class="font-monospace text-body">{{ keyFingerprint }}</span><br>
            Ask your contact to check that it matches the fingerprint under <strong>My Keys</strong> on their device.
        </div>
        <div v-else-if="keysUnreadable" class="form-text text-danger">
            These keys contain no usable encryption key. Check that you loaded a public.jwks.json from SBOsecure.
        </div>
    </div>
    <div class="mb-2 text-center">
        <button type="button" v-on:click="cancelEdit" class="btn btn-sm btn-secondary me-2">Cancel</button>
        <button type="button" v-on:click="saveContact" class="btn btn-sm btn-primary"
            v-bind:disabled="!contactInfo.name || !contactInfo.jwks">Done</button>
    </div>
</fieldset>
</div>`
};