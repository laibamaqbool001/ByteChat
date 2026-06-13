# 💬 ByteChat

> **Elevate Every Conversation** — A secure, forensic-enabled real-time chat application built with Node.js, MongoDB, and vanilla JavaScript.

![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=node.js&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-6.0+-47A248?style=for-the-badge&logo=mongodb&logoColor=white)
![Cloudinary](https://img.shields.io/badge/Cloudinary-Image_Storage-3448C5?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-4A90D9?style=for-the-badge)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [API Endpoints](#api-endpoints)
- [Security & Forensics](#security--forensics)

---

## 🌟 Overview

ByteChat is a full-stack real-time messaging application with a strong focus on **security**, **forensic integrity**, and **user experience**. Every message is encrypted end-to-end using AES-256-GCM, and every image upload is SHA-256 hashed for tamper detection. The application maintains a complete forensic audit trail of all user actions, message edits, and image modifications.

---

## ✨ Features

### 🔐 Authentication
- Email & password signup with input validation
- **Email verification** — activation link sent to inbox before account is active
- JWT authentication with access + refresh token rotation
- Secure logout — invalidates refresh token on server
- Forensic login tracking — IP, device, and login history stored silently

### 💬 Messaging
- Real-time text messaging between friends
- Image messaging with Cloudinary upload
- **Edit text messages** — shows `· edited` label to both parties
- **Delete messages** — soft delete with audit trail
- Smart polling with backoff on errors and rate limits

### 🖼️ Image Editor (WhatsApp-style)
Full canvas-based image editor built with HTML5 Canvas API:
- **Pen** — freehand drawing with color and size options
-  **Marker** — semi-transparent highlighter
-  **Eraser** — pixel-level erasing
-  **Text** — inline text placement (bold, italic, shadow, outline)
-  **Stickers** — 20 emoji stickers
-  **Crop** — drag to select or one-click square crop
-  **Filters** — 10 live preview filters (Normal, Vivid, Warm, Cold, B&W, Vintage, Fade, Neon, Drama, Matte)
-  **Adjustments** — Brightness, Contrast, Saturation, Blur
-  **Rotate** 90° clockwise
-  **Flip** horizontal mirror
-  **Undo** up to 30 steps
- Edited images re-uploaded and marked **"edited"** in database

### 👥 Friend System
- Search users by username
- Send / accept / decline / cancel friend requests
- Remove friends and block users
- Notification badge on pending requests

### 📞 Calls (UI)
- Voice and video call screens (WhatsApp-style dark UI)
- Mute, speaker, camera toggle, flip camera controls
- Call history panel

### 👤 Profile
- Edit display name and bio
- Upload profile picture via Cloudinary
- View friend count and encryption status

### 🎨 UI / UX
- 3D interactive effects — card tilt, bubble lift, button shimmer
- Animated particle background on auth screen (mouse-reactive)
- Decorative tagline with gradient divider lines
- PWA installable — install as desktop app
- ByteChat favicon in browser tab
- Toast notifications and smooth animations

---

## 🛠️ Tech Stack

### Backend
| Technology | Purpose |
|---|---|
| **Node.js** + **Express.js** | REST API server |
| **MongoDB** + **Mongoose** | Database & ODM |
| **JWT** | Access & refresh token auth |
| **bcryptjs** | Password hashing (12 rounds) |
| **Cloudinary** | Image storage & CDN |
| **Multer** + **Streamifier** | File upload handling |
| **Nodemailer** | Email verification (Gmail SMTP) |
| **crypto** (built-in) | SHA-256 hashing, AES-256-GCM encryption |
| **express-rate-limit** | Rate limiting per endpoint |

### Frontend
| Technology | Purpose |
|---|---|
| **Vanilla JavaScript** | All UI logic — no framework |
| **HTML5 Canvas API** | WhatsApp-style image editor |
| **Web Crypto API** | Client-side SHA-256 hash before upload |
| **CSS3** | 3D transforms, animations, gradients |
| **DM Sans** + **DM Mono** | Typography (Google Fonts) |
| **Service Worker** | PWA offline support & installability |

---

## 📁 Project Structure

```
bytechat/
│
├── bytechat frontend/
│   ├── index.html              # Single-page app (entire frontend)
│   ├── sw.js                   # Service worker (PWA installable)
│   └── .gitignore
│
└── ByteChat backend/
    ├── server.js               # Entry point
    ├── .env                    # Environment variables
    ├── .gitignore
    ├── package.json
    │
    ├── config/
    │   ├── cloudinary.js       # Cloudinary + multer + uploadToCloudinary()
    │   └── db.js               # MongoDB connection
    │
    ├── controllers/
    │   ├── auth.controller.js      # Signup, login, refresh, logout, activation
    │   ├── call.controller.js      # Call initiation and history
    │   ├── e2ee.controller.js      # End-to-end encryption key exchange
    │   ├── forensic.controller.js  # Forensic report generation
    │   ├── friend.controller.js    # Friend requests, block, remove
    │   ├── message.controller.js   # Send, edit, delete, image, tamper detection
    │   └── user.controller.js      # Profile, avatar, search
    │
    ├── middleware/
    │   ├── auth.middleware.js       # JWT protect middleware
    │   ├── metadata.middleware.js   # Silent IP/device capture
    │   └── Ratelimit.middleware.js  # Per-endpoint rate limiting
    │
    ├── models/
    │   ├── AuditLog.model.js        # Forensic action logs
    │   ├── Call.model.js            # Call records
    │   ├── EvidenceReport.model.js  # Generated evidence reports
    │   ├── FriendRequest.model.js   # Friend request records
    │   ├── Message.model.js         # Messages with edit/image history
    │   └── User.model.js            # Users with forensic profile
    │
    ├── routes/
    │   ├── auth.routes.js       # /api/auth/*
    │   ├── call.routes.js       # /api/calls/*
    │   ├── e2ee.routes.js       # /api/e2ee/*
    │   ├── forensic.routes.js   # /api/forensic/*
    │   ├── friend.routes.js     # /api/friends/*
    │   ├── message.routes.js    # /api/messages/*
    │   └── user.routes.js       # /api/users/*
    │
    ├── scripts/
    │   ├── generate-keys.js          # Generate encryption keys
    │   └── rotate-encryption-key.js  # Rotate AES keys
    │
    ├── services/
    │   ├── audit.service.js      # Forensic action logging
    │   ├── email.service.js      # Nodemailer activation emails
    │   └── evidence.service.js   # Evidence report generation
    │
    └── utils/
        ├── crypto.utils.js       # Cryptographic utilities
        ├── encryption.utils.js   # AES-256-GCM encrypt/decrypt
        ├── hash.utils.js         # HMAC-SHA256 content hashing
        └── token.utils.js        # JWT generation & verification
```

---

## 🚀 Installation

### Prerequisites
- Node.js 18+
- MongoDB Atlas account
- Cloudinary account
- Gmail account (for email verification)

### Steps

**1. Clone the repository**
```bash
git clone https://github.com/yourusername/bytechat.git
cd bytechat
```

**2. Install backend dependencies**
```bash
cd "ByteChat backend"
npm install
```

**3. Set up environment variables**
```bash
# Create .env file in ByteChat backend folder
# Fill in your values (see Environment Variables section below)
```

**4. Start the backend server**
```bash
nodemon server.js
# or
node server.js
```

**5. Open the frontend**
```
Open bytechat frontend/index.html in your browser
# or serve it:
npx serve "bytechat frontend" -p 3000
```

**6. Activate existing users (first time only)**

Run in MongoDB Atlas shell:
```js
db.users.updateMany({}, { $set: { isActive: true, emailVerified: true } })
```

---

## ⚙️ Environment Variables

Create a `.env` file in the `ByteChat backend` folder:

```env
# Server
PORT=5000
NODE_ENV=development

# MongoDB
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/bytechat

# JWT
JWT_SECRET=your_super_secret_jwt_key_min_32_chars
JWT_REFRESH_SECRET=your_refresh_secret_min_32_chars
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Cloudinary
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret

# Email (Gmail SMTP)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your@gmail.com
EMAIL_PASS=xxxx xxxx xxxx xxxx
EMAIL_FROM=ByteChat <your@gmail.com>
CLIENT_URL=http://localhost:3000
```

> **Gmail App Password:** Google Account → Security → 2-Step Verification → App Passwords → Create

---

## 📡 API Endpoints

### Auth — `/api/auth`
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/signup` | Register new account |
| `GET` | `/activate?token=` | Activate account via email link |
| `POST` | `/resend-activation` | Resend activation email |
| `POST` | `/login` | Login with email/username + password |
| `POST` | `/refresh` | Rotate access + refresh tokens |
| `POST` | `/logout` | Invalidate session |

### Messages — `/api/messages`
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/` | Send text message |
| `POST` | `/image` | Send image message |
| `GET` | `/conversation/:username` | Get conversation history |
| `PATCH` | `/:messageId` | Edit text message |
| `PATCH` | `/:messageId/image` | Edit/replace image message |
| `DELETE` | `/:messageId` | Delete message (soft delete) |
| `POST` | `/:messageId/verify-image` | Verify image authenticity |
| `GET` | `/:messageId/verify-text` | Verify text integrity |

### Friends — `/api/friends`
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/request` | Send friend request |
| `GET` | `/requests` | Get incoming + outgoing requests |
| `PATCH` | `/request/:id/:action` | Accept / decline / cancel |
| `DELETE` | `/remove` | Remove friend |
| `POST` | `/block` | Block user |

### Users — `/api/users`
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/me` | Get current user profile |
| `PATCH` | `/me` | Update display name and bio |
| `POST` | `/me/avatar` | Upload profile picture |
| `GET` | `/me/friends` | Get friends list |
| `GET` | `/search?q=` | Search users by username |

### Calls — `/api/calls`
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/` | Initiate a call |
| `PATCH` | `/:callId` | Update call status |
| `GET` | `/history` | Get call history |

---

## 🔒 Security & Forensics

ByteChat implements **4 layers of tamper detection**:

### Layer 1 — Transit Integrity (Images)
- Browser computes SHA-256 of image bytes **before** sending
- Server recomputes SHA-256 of received buffer
- Mismatch → `TAMPER_DETECTED` logged (possible MITM attack)
- Stored in `imageForensics.uploadIntegrityMatch`

### Layer 2 — Storage Integrity (All Messages)
- HMAC-SHA256 of plaintext computed before encryption at send time
- Every `getConversation` re-decrypts and re-hashes all messages
- Mismatch → `tampered: true` on message + audit log entry
- Detects direct MongoDB document manipulation

### Layer 3 — Image Authenticity (On-demand)
- Either party uploads a copy of an image to verify it
- Server hashes and compares against stored `serverHash`
- Detects crops, annotations, filters, re-saves, screenshots
- Logged as `IMAGE_VERIFIED` or `TAMPER_DETECTED`

### Layer 4 — Text Integrity (On-demand)
- Re-decrypts and recomputes HMAC of message
- Compares against hash stored at send time
- Proves database was never modified outside the application

### Additional Security
- **AES-256-GCM** encryption on all message content in database
- **Refresh token rotation** — old token invalidated on every refresh
- **IP + device forensic logging** on every login and action
- **Rate limiting** per endpoint (auth: 20/15min, conversations: 120/min)
- **Soft deletes** — deleted messages preserved in DB for forensics
- **Full edit history** — every text edit and image replacement archived in `editHistory` / `imageEditHistory`

---

## 👩‍💻 Developer

**Laiba Maqbool**
Built with Node.js, MongoDB & Vanilla JavaScript

---

## 📄 License

This project is licensed under the MIT License.

---

<div align="center">
  <strong>ByteChat — Secure. Encrypted. Private.</strong><br/>
  <em>Elevate Every Conversation</em>
</div>
