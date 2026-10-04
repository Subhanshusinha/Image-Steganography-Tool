<div align="center">

<br/>

<img src="https://img.shields.io/badge/-StealthGuard-4f46e5?style=for-the-badge&logo=shield&logoColor=white" alt="StealthGuard" height="50"/>

<br/><br/>

**Hide secrets inside images. Invisible. Encrypted. 100% Local.**

<br/>

[![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-F7DF1E?style=flat-square&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![Web Crypto API](https://img.shields.io/badge/Web_Crypto-AES--256--GCM-4f46e5?style=flat-square&logo=w3c&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.x-38B2AC?style=flat-square&logo=tailwind-css&logoColor=white)](https://tailwindcss.com)
[![Zero Backend](https://img.shields.io/badge/Backend-None-brightgreen?style=flat-square)](https://github.com/Subhanshusinha/Image-Steganography-Tool)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-ff69b4?style=flat-square)](https://github.com/Subhanshusinha/Image-Steganography-Tool/pulls)

<br/>

</div>

---

## 🌟 What is StealthGuard?

**StealthGuard** is a browser-based steganography tool that lets you **invisibly embed secret text or files inside ordinary PNG images** — with military-grade AES-256-GCM encryption. The encoded image looks identical to the original. No server. No upload. No tracking. Everything runs **directly inside your browser**.

> *"The best-kept secret is the one no one knows exists."*

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔐 Military-Grade Encryption
Uses **AES-256-GCM** via the native Web Crypto API with **PBKDF2** key derivation (100,000 iterations + random salt). Your data is unbreakable without the correct password.

</td>
<td width="50%">

### 🖼️ Invisible Steganography
Hides your data in the **Least Significant Bits** of image pixels. The human eye cannot detect the difference. Works with any PNG image.

</td>
</tr>
<tr>
<td width="50%">

### 🎲 Distributed Bit Spreading
Data bits are **randomly distributed** across the entire image using a seeded **Fisher-Yates PRNG shuffle**, preventing localized pixel artifacts.

</td>
<td width="50%">

### 📦 Any File Support
Not just text — hide **entire files** (PDFs, ZIPs, Word documents, code files) inside an image. Up to the image's full pixel capacity.

</td>
</tr>
<tr>
<td width="50%">

### 🔬 Visual Diff Analyzer
Compare an original image with an encoded one using a pixel-level **diff heat map** — highlights every single modified pixel in red.

</td>
<td width="50%">

### 📱 Fully Responsive
Works beautifully on **desktop, tablet, and mobile** with a dedicated bottom navigation bar, touch-friendly inputs, and a glassmorphism UI.

</td>
</tr>
</table>

---

## 🚀 Quick Start

> No installation required. No dependencies to install. Just open and use.

```bash
# 1. Clone the repository
git clone https://github.com/Subhanshusinha/Image-Steganography-Tool.git

# 2. Open in your browser
cd Image-Steganography-Tool
open index.html   # macOS
start index.html  # Windows
```

That's it. The app runs entirely offline.

---

## 📖 How to Use

### 🔵 Step 1 — Hide Data
1. Open the app and click **Hide Data** in the navigation.
2. Drag & drop a **PNG image** as your carrier (cover image).
3. Type a secret message **or** upload any file to hide.
4. *(Optional)* Enter a strong password for AES-256 encryption.
5. Click **Encrypt & Embed** → download your secured PNG.

### 🟣 Step 2 — Share the Image
Send the PNG via **email, Discord, Slack, Google Drive, Dropbox, or USB**. The image is visually indistinguishable from the original.

### 🟢 Step 3 — Extract Data
1. Open the **Extract Data** tab.
2. Upload the secured PNG image.
3. Enter the password (if one was set).
4. Click **Extract Payload** to recover the original text or file.

---

## ⚠️ Critical Warning

> [!CAUTION]
> Steganography relies on **exact pixel values**. If the image is re-compressed, resized, or converted (e.g. from PNG to JPEG), the hidden payload is **permanently and irrecoverably destroyed**.

| ✅ Safe to Use | ❌ Destroys Payload |
|---|---|
| Email (file attachment) | WhatsApp (compresses images) |
| Discord (send as file) | Twitter / X |
| Google Drive | Instagram |
| Dropbox | Facebook Messenger |
| Slack | Telegram (if not sent as file) |
| USB / Local transfer | Any image re-encoding service |

---

## 📂 Project Structure

```
Image-Steganography-Tool/
│
├── 📄 index.html               # Single-page app entry point
│
├── 📁 assets/
│   └── 📁 css/
│       └── styles.css          # Animations, glassmorphism, mobile nav
│
├── 📁 src/
│   ├── app.js                  # UI logic, routing, event handlers
│   └── 📁 core/
│       ├── crypto.js           # AES-256-GCM Web Crypto wrapper
│       ├── prng.js             # Seeded Fisher-Yates index generator
│       └── steganography.js    # LSB encode/decode engine
│
├── .gitignore
└── README.md
```

---

## 🛡️ Security Architecture

```
User Payload
     │
     ▼
[pako DEFLATE compression]
     │
     ▼
[AES-256-GCM Encryption]  ←── PBKDF2(password, random_salt, 100k iterations)
     │
     ▼
[Packet: MAGIC | flags | metaLen | payloadLen | metadata | ciphertext]
     │
     ▼
[Fisher-Yates PRNG] → Random pixel indices across entire image
     │
     ▼
[LSB Write: pixel_bit = (pixel & 0xFE) | data_bit]
     │
     ▼
     📷 Output PNG (visually identical to original)
```

---

## 🔒 Privacy Guarantee

- ✅ **Zero network requests** — all processing is 100% local
- ✅ **No cookies, no analytics, no tracking** of any kind
- ✅ **No data ever leaves your device**
- ✅ **Open source** — inspect every line of code yourself
- ✅ **Works fully offline** after the initial page load

---

## 🧰 Tech Stack

| Technology | Purpose |
|---|---|
| Vanilla JavaScript (ES2022) | Core application logic |
| Web Crypto API (native) | AES-256-GCM encryption, PBKDF2 key derivation |
| HTML5 Canvas API (native) | Image pixel manipulation |
| Tailwind CSS (CDN) | Responsive UI styling |
| pako.js | DEFLATE payload compression |
| localStorage | Session statistics (local only) |

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

<div align="center">

**Built with ❤️ by [Subhanshu Sinha](https://github.com/Subhanshusinha)**

⭐ Star this repo if you found it useful!

</div>
