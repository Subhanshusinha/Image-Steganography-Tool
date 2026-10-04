class CryptoEngine {
    static async encryptBytes(dataBytes, password) {
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);
        const keyMaterial = await crypto.subtle.importKey(
            'raw', passwordBuffer, { name: 'PBKDF2' }, false, ['deriveKey']
        );
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
            keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
        );
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, dataBytes);

        const result = new Uint8Array(16 + 12 + encrypted.byteLength);
        result.set(salt, 0);
        result.set(iv, 16);
        result.set(new Uint8Array(encrypted), 28);
        return result;
    }

    static async decryptBytes(encryptedData, password) {
        const salt = encryptedData.slice(0, 16);
        const iv = encryptedData.slice(16, 28);
        const encrypted = encryptedData.slice(28);

        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);
        const keyMaterial = await crypto.subtle.importKey(
            'raw', passwordBuffer, { name: 'PBKDF2' }, false, ['deriveKey']
        );
        const key = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
            keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
        );
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
        return new Uint8Array(decrypted);
    }
}
