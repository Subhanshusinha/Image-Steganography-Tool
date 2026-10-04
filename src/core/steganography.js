class Steganography {
    constructor() {
        this.MAGIC = [0x53, 0x47, 0x32, 0x00]; // SG2\0
    }

    // --- Core bit manipulation ---
    _writeBitsToImage(imageData, bits, password) {
        const gen = new IndexGenerator(imageData.data.length, password);
        for (let i = 0; i < bits.length; i++) {
            const idx = gen.next();
            imageData.data[idx] = (imageData.data[idx] & 0xFE) | bits[i];
        }
    }

    _readBitsFromImage(imageData, count, password) {
        const gen = new IndexGenerator(imageData.data.length, password);
        const bits = new Uint8Array(count);
        for (let i = 0; i < count; i++) {
            bits[i] = imageData.data[gen.next()] & 1;
        }
        return bits;
    }

    _bytesToBits(bytes) {
        const bits = new Uint8Array(bytes.length * 8);
        for (let i = 0; i < bytes.length; i++) {
            for (let b = 7; b >= 0; b--) {
                bits[i * 8 + (7 - b)] = (bytes[i] >> b) & 1;
            }
        }
        return bits;
    }

    _bitsToBytes(bits) {
        const bytes = new Uint8Array(bits.length / 8);
        for (let i = 0; i < bytes.length; i++) {
            let val = 0;
            for (let b = 0; b < 8; b++) {
                val = (val << 1) | bits[i * 8 + b];
            }
            bytes[i] = val;
        }
        return bytes;
    }

    // Encode: takes raw Uint8Array payload and metadata object
    async encode(imageData, payloadBytes, metadata, password) {
        // 1. Compress payload
        let compressed = payloadBytes;
        try {
            if (window.pako) compressed = pako.deflate(payloadBytes);
        } catch(e) {}

        // 2. Encrypt if password given
        let finalPayload = compressed;
        if (password) {
            finalPayload = await CryptoEngine.encryptBytes(compressed, password);
        }

        // 3. Build metadata bytes
        const metaStr = JSON.stringify(metadata);
        const metaBytes = new TextEncoder().encode(metaStr);

        // 4. Build full data packet:
        // [4 magic][1 flags][2 metaLen][4 payloadLen][metaBytes][payloadBytes]
        const flags = (password ? 0x01 : 0x00) | (window.pako ? 0x02 : 0x00);
        const header = new Uint8Array(4 + 1 + 2 + 4);
        header.set(this.MAGIC, 0);
        header[4] = flags;
        new DataView(header.buffer).setUint16(5, metaBytes.length, false);
        new DataView(header.buffer).setUint32(7, finalPayload.length, false);

        const packet = new Uint8Array(header.length + metaBytes.length + finalPayload.length);
        packet.set(header, 0);
        packet.set(metaBytes, header.length);
        packet.set(finalPayload, header.length + metaBytes.length);

        // 5. Capacity check
        const maxBytes = Math.floor(imageData.data.length / 8);
        if (packet.length > maxBytes) {
            throw new Error(`Payload too large. Max: ${maxBytes} bytes, needed: ${packet.length} bytes.`);
        }

        // 6. Write bits
        const newData = new ImageData(
            new Uint8ClampedArray(imageData.data),
            imageData.width,
            imageData.height
        );
        this._writeBitsToImage(newData, this._bytesToBits(packet), password);

        // 7. Update stats
        try {
            localStorage.setItem('steg_enc', (parseInt(localStorage.getItem('steg_enc') || '0') + 1).toString());
            localStorage.setItem('steg_bytes', (parseInt(localStorage.getItem('steg_bytes') || '0') + packet.length).toString());
        } catch(e) {}

        return newData;
    }

    async decode(imageData, password) {
        // 1. Read header: 11 bytes = 88 bits
        const headerBits = this._readBitsFromImage(imageData, 11 * 8, password);
        const headerBytes = this._bitsToBytes(headerBits);

        // 2. Verify magic
        if (headerBytes[0] !== this.MAGIC[0] || headerBytes[1] !== this.MAGIC[1] ||
            headerBytes[2] !== this.MAGIC[2] || headerBytes[3] !== this.MAGIC[3]) {
            throw new Error('No hidden data found in this image, or wrong password was used.');
        }

        const flags = headerBytes[4];
        const wasEncrypted = (flags & 0x01) !== 0;
        const wasCompressed = (flags & 0x02) !== 0;
        const dv = new DataView(headerBytes.buffer);
        const metaLen = dv.getUint16(5, false);
        const payloadLen = dv.getUint32(7, false);

        // 3. Validate
        const totalBytes = 11 + metaLen + payloadLen;
        if (totalBytes > Math.floor(imageData.data.length / 8)) {
            throw new Error('Corrupted data or wrong password.');
        }

        // 4. Re-read all data from scratch (need consistent IndexGenerator state)
        const allBits = this._readBitsFromImage(imageData, totalBytes * 8, password);
        const allBytes = this._bitsToBytes(allBits);

        const metaBytes = allBytes.slice(11, 11 + metaLen);
        let payloadBytes = allBytes.slice(11 + metaLen);

        // 5. Decrypt
        if (wasEncrypted) {
            if (!password) throw new Error('This image is encrypted. Please provide the password.');
            payloadBytes = await CryptoEngine.decryptBytes(payloadBytes, password);
        }

        // 6. Decompress
        if (wasCompressed && window.pako) {
            try {
                payloadBytes = pako.inflate(payloadBytes);
            } catch(e) {
                // might not have been compressed in edge cases
            }
        }

        // 7. Parse metadata & return
        const metadata = JSON.parse(new TextDecoder().decode(metaBytes));

        try {
            localStorage.setItem('steg_dec', (parseInt(localStorage.getItem('steg_dec') || '0') + 1).toString());
        } catch(e) {}

        if (metadata.type === 'text') {
            return { type: 'text', data: new TextDecoder().decode(payloadBytes) };
        } else {
            return { type: 'file', data: payloadBytes, name: metadata.name, mime: metadata.mime };
        }
    }
}
