
// Steganography Implementation
        class Steganography {
            constructor() {
                this.magicBytes = 'STEG'; // Used to mark the start of hidden data
            }

            // Convert string to binary
            stringToBinary(str) {
                return str.split('').map(char => {
                    return char.charCodeAt(0).toString(2).padStart(8, '0');
                }).join('');
            }

            // Convert binary to string
            binaryToString(binary) {
                let str = '';
                for (let i = 0; i < binary.length; i += 8) {
                    str += String.fromCharCode(parseInt(binary.substr(i, 8), 2));
                }
                return str;
            }

            // Encode message into image data
            async encode(imageData, message, password = null) {
                if (password) {
                    message = await this.encryptMessage(message, password);
                }

                // Prepare the message: magic bytes + length + message
                const binaryMessage = this.stringToBinary(this.magicBytes + String.fromCharCode(message.length) + message);
                
                // Check if the message will fit in the image
                const requiredPixels = binaryMessage.length * 4; // *4 because we can change RGBA for each pixel
                if (requiredPixels > imageData.data.length) {
                    throw new Error('Message is too long for this image');
                }

                // Copy the image data to avoid modifying the original
                const newImageData = new ImageData(
                    new Uint8ClampedArray(imageData.data),
                    imageData.width,
                    imageData.height
                );

                let pixelIndex = 0;
                for (let i = 0; i < binaryMessage.length; i++) {
                    const bit = parseInt(binaryMessage[i]);
                    const currentPixel = pixelIndex % 4; // 0: R, 1: G, 2: B, 3: A

                    // Replace the least significant bit with our message bit
                    newImageData.data[pixelIndex] = (newImageData.data[pixelIndex] & 0xFE) | bit;
                    pixelIndex++;
                }

                return newImageData;
            }

            // Decode message from image data
            async decode(imageData, password = null) {
                // First, find the magic bytes marking the start of the message
                let binaryMessage = '';
                let foundHeader = false;
                let headerPos = 0;
                let messageLength = 0;
                
                for (let i = 0; i < imageData.data.length; i++) {
                    // Extract the LSB
                    const bit = imageData.data[i] & 1;
                    binaryMessage += bit.toString();
                    
                    // Check if we have enough bits to check for the header
                    if (!foundHeader && binaryMessage.length >= 8 * (this.magicBytes.length + 1)) {
                        // Try to parse the header (magic bytes + message length)
                        const potentialMagicBytes = this.binaryToString(binaryMessage.substr(0, 8 * this.magicBytes.length));
                        if (potentialMagicBytes === this.magicBytes) {
                            // We found the header, now get the message length
                            messageLength = this.binaryToString(binaryMessage.substr(8 * this.magicBytes.length, 8)).charCodeAt(0);
                            foundHeader = true;
                            headerPos = this.magicBytes.length + 1; // +1 for the length byte
                            binaryMessage = binaryMessage.substr(8 * headerPos); // Get rid of the header
                        } else {
                            // Remove the first byte and continue searching
                            binaryMessage = binaryMessage.substr(8);
                        }
                    }
                    
                    // If we found the header, check if we've read enough bits
                    if (foundHeader && binaryMessage.length >= messageLength * 8) {
                        // Extract exactly the message
                        const messageBinary = binaryMessage.substr(0, messageLength * 8);
                        let message = this.binaryToString(messageBinary);
                        
                        // If password was provided, try to decrypt
                        if (password) {
                            try {
                                message = await this.decryptMessage(message, password);
                            } catch (e) {
                                throw new Error('Incorrect password or corrupted message');
                            }
                        }
                        
                        return message;
                    }
                }
                
                throw new Error('No hidden message found in this image');
            }

            // Encrypt message with password using Web Crypto API
            async encryptMessage(message, password) {
                // Prepare the key from password
                const encoder = new TextEncoder();
                const passwordBuffer = encoder.encode(password);
                const keyMaterial = await crypto.subtle.importKey(
                    'raw',
                    passwordBuffer,
                    { name: 'PBKDF2' },
                    false,
                    ['deriveBits', 'deriveKey']
                );
                
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const key = await crypto.subtle.deriveKey(
                    {
                        name: 'PBKDF2',
                        salt: salt,
                        iterations: 100000,
                        hash: 'SHA-256'
                    },
                    keyMaterial,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['encrypt', 'decrypt']
                );
                
                // Generate IV and encrypt
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const encrypted = await crypto.subtle.encrypt(
                    {
                        name: 'AES-GCM',
                        iv: iv
                    },
                    key,
                    encoder.encode(message)
                );
                
                // Combine salt + iv + encrypted data and convert to base64 for storage
                const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
                combined.set(salt, 0);
                combined.set(iv, salt.length);
                combined.set(new Uint8Array(encrypted), salt.length + iv.length);
                
                return btoa(String.fromCharCode(...combined));
            }

            // Decrypt message with password using Web Crypto API
            async decryptMessage(encryptedBase64, password) {
                // Convert from base64 to Uint8Array
                const binaryString = atob(encryptedBase64);
                const encryptedBuffer = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    encryptedBuffer[i] = binaryString.charCodeAt(i);
                }
                
                // Extract salt, iv and encrypted data
                const salt = encryptedBuffer.slice(0, 16);
                const iv = encryptedBuffer.slice(16, 16 + 12);
                const encrypted = encryptedBuffer.slice(16 + 12);
                
                // Prepare the key from password
                const encoder = new TextEncoder();
                const passwordBuffer = encoder.encode(password);
                const keyMaterial = await crypto.subtle.importKey(
                    'raw',
                    passwordBuffer,
                    { name: 'PBKDF2' },
                    false,
                    ['deriveBits', 'deriveKey']
                );
                
                const key = await crypto.subtle.deriveKey(
                    {
                        name: 'PBKDF2',
                        salt: salt,
                        iterations: 100000,
                        hash: 'SHA-256'
                    },
                    keyMaterial,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['decrypt']
                );
                
                // Decrypt
                const decrypted = await crypto.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: iv
                    },
                    key,
                    encrypted
                );
                
                return new TextDecoder().decode(decrypted);
            }
        }

        // UI Implementation
        document.addEventListener('DOMContentLoaded', () => {
            const stego = new Steganography();
            const encodeTab = document.getElementById('encode-tab');
            const decodeTab = document.getElementById('decode-tab');
            const aboutTab = document.getElementById('about-tab');
            const encodeSection = document.getElementById('encode-section');
            const decodeSection = document.getElementById('decode-section');
            const aboutSection = document.getElementById('about-section');
            
            const encodeDropzone = document.getElementById('encode-dropzone');
            const encodeImageContainer = document.getElementById('encode-image-container');
            const encodeCanvas = document.getElementById('encode-canvas');
            const encodeRemoveBtn = document.getElementById('encode-remove-btn');
            const secretMessage = document.getElementById('secret-message');
            const password = document.getElementById('password');
            const encodeBtn = document.getElementById('encode-btn');
            const encodeResult = document.getElementById('encode-result');
            const encodeResultCanvas = document.getElementById('encode-result-canvas');
            const downloadEncodeResult = document.getElementById('download-encode-result');
            const messageCounter = document.getElementById('message-counter');
            
            const decodeDropzone = document.getElementById('decode-dropzone');
            const decodeImageContainer = document.getElementById('decode-image-container');
            const decodeCanvas = document.getElementById('decode-canvas');
            const decodeRemoveBtn = document.getElementById('decode-remove-btn');
            const decodePassword = document.getElementById('decode-password');
            const decodeBtn = document.getElementById('decode-btn');
            const decodeResult = document.getElementById('decode-result');
            const extractedMessage = document.getElementById('extracted-message');
            const copyMessage = document.getElementById('copy-message');
            
            let encodeImageData = null;
            let decodeImageData = null;
            
            // Tab switching
            encodeTab.addEventListener('click', () => {
                encodeTab.classList.add('tab-active');
                encodeTab.classList.remove('text-gray-500');
                encodeTab.classList.add('text-blue-600');
                
                decodeTab.classList.remove('tab-active');
                decodeTab.classList.add('text-gray-500');
                decodeTab.classList.remove('text-blue-600');
                
                aboutTab.classList.remove('tab-active');
                aboutTab.classList.add('text-gray-500');
                aboutTab.classList.remove('text-blue-600');
                
                encodeSection.classList.remove('hidden');
                decodeSection.classList.add('hidden');
                aboutSection.classList.add('hidden');
            });
            
            decodeTab.addEventListener('click', () => {
                encodeTab.classList.remove('tab-active');
                encodeTab.classList.add('text-gray-500');
                encodeTab.classList.remove('text-blue-600');
                
                decodeTab.classList.add('tab-active');
                decodeTab.classList.remove('text-gray-500');
                decodeTab.classList.add('text-blue-600');
                
                aboutTab.classList.remove('tab-active');
                aboutTab.classList.add('text-gray-500');
                aboutTab.classList.remove('text-blue-600');
                
                encodeSection.classList.add('hidden');
                decodeSection.classList.remove('hidden');
                aboutSection.classList.add('hidden');
            });
            
            aboutTab.addEventListener('click', () => {
                encodeTab.classList.remove('tab-active');
                encodeTab.classList.add('text-gray-500');
                encodeTab.classList.remove('text-blue-600');
                
                decodeTab.classList.remove('tab-active');
                decodeTab.classList.add('text-gray-500');
                decodeTab.classList.remove('text-blue-600');
                
                aboutTab.classList.add('tab-active');
                aboutTab.classList.remove('text-gray-500');
                aboutTab.classList.add('text-blue-600');
                
                encodeSection.classList.add('hidden');
                decodeSection.classList.add('hidden');
                aboutSection.classList.remove('hidden');
            });
            
            // Encode section
            encodeDropzone.addEventListener('click', () => {
                const input = document.createElement('input');
                input.type = 'file';
                input.accept = 'image/png,image/jpeg';
                
                input.onchange = e => {
                    const file = e.target.files[0];
                    if (file) {
                        loadImageForEncoding(file);
                    }
                };
                
                input.click();
            });
            
            encodeDropzone.addEventListener('dragover', e => {
                e.preventDefault();
                encodeDropzone.classList.add('active');
            });
            
            encodeDropzone.addEventListener('dragleave', e => {
                e.preventDefault();
                encodeDropzone.classList.remove('active');
            });
            
            encodeDropzone.addEventListener('drop', e => {
                e.preventDefault();
                encodeDropzone.classList.remove('active');
                
                const file = e.dataTransfer.files[0];
                if (file && (file.type === 'image/png' || file.type === 'image/jpeg')) {
                    loadImageForEncoding(file);
                }
            });
            
            encodeRemoveBtn.addEventListener('click', () => {
                encodeImageContainer.classList.add('hidden');
                encodeDropzone.classList.remove('hidden');
                encodeImageData = null;
                encodeResult.classList.add('hidden');
            });
            
            secretMessage.addEventListener('input', () => {
                const count = secretMessage.value.length;
                messageCounter.textContent = `${count}/1000 characters`;
                
                if (count > 1000) {
                    messageCounter.classList.add('text-red-500');
                    messageCounter.classList.remove('text-gray-500');
                } else {
                    messageCounter.classList.remove('text-red-500');
                    messageCounter.classList.add('text-gray-500');
                }
            });
            
            encodeBtn.addEventListener('click', async () => {
                if (!encodeImageData) {
                    alert('Please upload an image first');
                    return;
                }
                
                if (!secretMessage.value) {
                    alert('Please enter a secret message');
                    return;
                }
                
                if (secretMessage.value.length > 1000) {
                    alert('Message is too long. Maximum 1000 characters allowed.');
                    return;
                }
                
                try {
                    encodeBtn.disabled = true;
                    encodeBtn.textContent = 'Hiding message...';
                    
                    const encodedImage = await stego.encode(encodeImageData, secretMessage.value, password.value || null);
                    const ctx = encodeResultCanvas.getContext('2d');
                    
                    encodeResultCanvas.width = encodedImage.width;
                    encodeResultCanvas.height = encodedImage.height;
                    ctx.putImageData(encodedImage, 0, 0);
                    
                    encodeResult.classList.remove('hidden');
                    
                    // Scroll to result
                    encodeResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                } catch (e) {
                    alert('Error: ' + e.message);
                } finally {
                    encodeBtn.disabled = false;
                    encodeBtn.textContent = 'Hide Message';
                }
            });
            
            downloadEncodeResult.addEventListener('click', () => {
                const link = document.createElement('a');
                link.download = 'secret-image.png';
                link.href = encodeResultCanvas.toDataURL('image/png');
                link.click();
            });
            
            // Decode section
            decodeDropzone.addEventListener('click', () => {
                const input = document.createElement('input');
                input.type = 'file';
                input.accept = 'image/png,image/jpeg';
                
                input.onchange = e => {
                    const file = e.target.files[0];
                    if (file) {
                        loadImageForDecoding(file);
                    }
                };
                
                input.click();
            });
            
            decodeDropzone.addEventListener('dragover', e => {
                e.preventDefault();
                decodeDropzone.classList.add('active');
            });
            
            decodeDropzone.addEventListener('dragleave', e => {
                e.preventDefault();
                decodeDropzone.classList.remove('active');
            });
            
            decodeDropzone.addEventListener('drop', e => {
                e.preventDefault();
                decodeDropzone.classList.remove('active');
                
                const file = e.dataTransfer.files[0];
                if (file && (file.type === 'image/png' || file.type === 'image/jpeg')) {
                    loadImageForDecoding(file);
                }
            });
            
            decodeRemoveBtn.addEventListener('click', () => {
                decodeImageContainer.classList.add('hidden');
                decodeDropzone.classList.remove('hidden');
                decodeImageData = null;
                decodeResult.classList.add('hidden');
            });
            
            decodeBtn.addEventListener('click', async () => {
                if (!decodeImageData) {
                    alert('Please upload an image first');
                    return;
                }
                
                try {
                    decodeBtn.disabled = true;
                    decodeBtn.textContent = 'Extracting message...';
                    
                    const message = await stego.decode(decodeImageData, decodePassword.value || null);
                    extractedMessage.textContent = message;
                    
                    decodeResult.classList.remove('hidden');
                    
                    // Scroll to result
                    decodeResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                } catch (e) {
                    alert('Error: ' + e.message);
                } finally {
                    decodeBtn.disabled = false;
                    decodeBtn.textContent = 'Extract Message';
                }
            });
            
            copyMessage.addEventListener('click', () => {
                navigator.clipboard.writeText(extractedMessage.textContent)
                    .then(() => {
                        const originalText = copyMessage.textContent;
                        copyMessage.textContent = 'Copied!';
                        setTimeout(() => {
                            copyMessage.textContent = originalText;
                        }, 2000);
                    })
                    .catch(err => {
                        console.error('Failed to copy text: ', err);
                    });
            });
            
            // Helper functions
            function loadImageForEncoding(file) {
                const reader = new FileReader();
                
                reader.onload = e => {
                    const img = new Image();
                    img.onload = () => {
                        encodeCanvas.width = img.width;
                        encodeCanvas.height = img.height;
                        const ctx = encodeCanvas.getContext('2d');
                        ctx.drawImage(img, 0, 0);
                        
                        encodeImageData = ctx.getImageData(0, 0, img.width, img.height);
                        encodeDropzone.classList.add('hidden');
                        encodeImageContainer.classList.remove('hidden');
                    };
                    img.src = e.target.result;
                };
                
                reader.readAsDataURL(file);
            }
            
            function loadImageForDecoding(file) {
                const reader = new FileReader();
                
                reader.onload = e => {
                    const img = new Image();
                    img.onload = () => {
                        decodeCanvas.width = img.width;
                        decodeCanvas.height = img.height;
                        const ctx = decodeCanvas.getContext('2d');
                        ctx.drawImage(img, 0, 0);
                        
                        decodeImageData = ctx.getImageData(0, 0, img.width, img.height);
                        decodeDropzone.classList.add('hidden');
                        decodeImageContainer.classList.remove('hidden');
                    };
                    img.src = e.target.result;
                };
                
                reader.readAsDataURL(file);
            }
        });
 