# 🕵️‍♂️ Image Steganography Tool

A browser-based tool to hide and extract secret messages in images using the Least Significant Bit (LSB) technique. Built using HTML, CSS, and JavaScript with optional password-based encryption.

![image](https://github.com/user-attachments/assets/5a578f2e-3753-4217-bde3-2d106c35bfbe)

---

## 🔐 Features

- 🔏 Hide secret text messages inside PNG/JPG images
- 🛡️ Optional password encryption using Web Crypto API (AES-GCM)
- 🖼️ Uses Least Significant Bit (LSB) steganography
- 💻 100% client-side — no server or upload needed
- 📱 Responsive UI (mobile & desktop friendly)
- 🔎 Extract hidden messages easily with or without password

---

## 🛠️ Tech Stack

- HTML5 + CSS3 + JavaScript
- TailwindCSS for styling
- HTML5 Canvas API for image manipulation
- Web Crypto API for password-based encryption

---

## 🧪 How to Use

### 🔐 Hide a Message
1. Open the app (open `index.html` in browser)
2. Upload a PNG or JPG image
3. Type your secret message (max 1000 characters)
4. (Optional) Add a password to encrypt the message
5. Click **"Hide Message"** → download the modified image

### 🔓 Extract a Message
1. Open the app again
2. Upload the image with hidden message
3. (If used) enter the correct password
4. Click **"Extract Message"** to reveal the hidden text

---

## 📁 Project Structure

📦 image-steganography-tool/
├── index.html # UI Layout
├── styles.css # Custom styling (includes Tailwind tweaks)
├── app.js # Core logic for encoding/decoding
└── README.md # Project documentation


---

## 🌐 Live Demo (Optional)

You can host this project using GitHub Pages:

1. Go to your GitHub repo → Settings → Pages
2. Under "Source", choose `main` branch and root (`/`)
3. Click Save — GitHub will give you a public URL like:  
   `https://your-username.github.io/image-steganography-tool`

---

## 📌 Use Cases

- Securely share private messages
- Demonstrate cryptography + steganography
- Educational projects or cybersecurity demos
- Fun hidden image games

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 👨‍💻 Author

📫 **Subhanshu Sinha**


---


