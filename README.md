# StealthGuard: Advanced Image Steganography Tool

<div align="center">
  <p><strong>Securely embed encrypted payloads (files & text) invisibly into PNG images using your browser.</strong></p>
  <img src="https://img.shields.io/badge/Vanilla-JS-yellow?style=for-the-badge&logo=javascript" alt="Vanilla JS">
  <img src="https://img.shields.io/badge/Web-Crypto_API-blue?style=for-the-badge&logo=w3c" alt="Web Crypto">
  <img src="https://img.shields.io/badge/Tailwind-CSS-38B2AC?style=for-the-badge&logo=tailwind-css" alt="Tailwind CSS">
  <img src="https://img.shields.io/badge/100%25-Local-brightgreen?style=for-the-badge" alt="100% Local">
</div>

---

## 🚀 Features

- **100% Local Processing:** Zero server communication. All encryption, compression, and steganography happen directly in your browser.
- **AES-256-GCM Encryption:** Payloads are encrypted using the native Web Crypto API before being embedded.
- **Any File Support:** Hide text messages or entire files (PDFs, ZIPs, Docs) inside a carrier image.
- **Lossless LSB Steganography:** Data is woven into the Least Significant Bits of the image pixels, making the payload completely invisible to the human eye.
- **Distributed Spreading:** Uses a seeded Fisher-Yates PRNG to randomly scatter the payload bits across the image, preventing localized artifacting.
- **Visual Diff Analysis:** Compare an original image with a stego-image to visualize the exact modified pixels.
- **Premium UI:** Built with a beautiful, responsive, glassmorphism Tailwind CSS interface featuring smooth animations.

## 📂 Project Structure

```
├── assets/
│   └── css/
│       └── styles.css          # Custom animations and glassmorphism utilities
├── src/
│   ├── app.js                  # Main application UI logic and routing
│   └── core/
│       ├── crypto.js           # AES-256 Web Crypto abstraction layer
│       ├── prng.js             # Fisher-Yates shuffle generator
│       └── steganography.js    # Core LSB encoding/decoding engine
├── index.html                  # Single Page Application (SPA) view
└── README.md
```

## 🛠️ Usage Guide

### 1. Hide Data
1. Open `index.html` in any modern web browser.
2. Navigate to the **Hide Data** tab.
3. Drag & Drop a carrier PNG image.
4. Enter a secret text message or select a file to hide.
5. (Optional) Enter an AES-256 password to encrypt the payload.
6. Click **Encrypt & Embed**. Download the generated PNG.

### 2. Extract Data
1. Navigate to the **Extract Data** tab.
2. Drag & Drop the secured PNG image.
3. Enter the exact password used during encryption.
4. Click **Extract Payload** to retrieve your hidden text or file.

### 3. Visual Analysis
1. Navigate to the **Analysis** tab.
2. Upload the Original PNG and the Encoded PNG.
3. Click **Run Visual Comparison** to generate a diff-map highlighting the exact pixels that were altered by the steganography process.

## ⚠️ Important Warning
Steganography relies on exact pixel-level accuracy. If you share the encoded image via a service that compresses or resizes images (like standard WhatsApp, Twitter, or Instagram), the hidden payload will be **permanently destroyed**. 

**Always share the output image via lossless methods:**
- Email (as a file attachment)
- Discord / Slack (sent as a file)
- ZIP archives
- Google Drive / Dropbox

## 🛡️ Privacy
This application has **no backend**. It does not collect telemetry, send analytics, or transmit your images/data anywhere. All files are processed strictly within the memory of your local machine.

---
*Built with modern web standards.*
