# 🚀 Sec Chat

**Sec Chat** is a modern, secure, end-to-end encrypted chat platform built for privacy and usability.  
All messages and passwords are encrypted using public/private key cryptography, ensuring that only you and your chat partner can ever read your conversations.  
With a beautiful, responsive UI and advanced features like vanish mode, dynamic user search, and profile management, Sec Chat is the next-generation messaging solution for privacy-conscious users.

---

## ✨ Features

- **End-to-End Encryption:** All chats are encrypted with public/private key cryptography. Only you and your recipient can decrypt messages.
- **Encrypted Storage:** Passwords and chat data are securely encrypted in the database.
- **Vanish Mode:** Chat without leaving a trace—no messages are stored, and all vanish on logout or reload.
- **User Search:** Instantly find users with dynamic, real-time search.
- **Profile Management:** Edit your profile, set a profile picture, or delete your account.
- **Seen & Typing Notifications:** Know when your messages are seen and when someone is typing.
- **Login, Register, Forgot Password:** Full authentication flow with secure password hashing.
- **Clear Chat:** One-click to delete your chat history from the database.
- **Online/Offline Status:** See who’s online with real-time status icons.
- **Screenshot Option:** Capture and share your chat screen easily.
- **Responsive UI:** Pitch-black, glassmorphic, and animated gradient design, inspired by WhatsApp and Telegram.
- **Dockerized Deployment:** Easy to run anywhere.

---

## 🕵️‍♂️ Security

- **End-to-End Encryption:** Messages are encrypted on the client with the recipient's public key and can only be decrypted with their private key.
- **Password Hashing:** User passwords are hashed and salted before storage.
- **Vanish Mode:** No chat data is stored in the database; all vanish mode messages are ephemeral.
- **No Plaintext Storage:** Neither passwords nor messages are ever stored or transmitted in plaintext.

---

## 📸 Screenshots

> _Add your screenshots here! For example:_
>
> ![Chat UI](screenshots/chat-ui.png)
> ![Vanish Mode](screenshots/vanish-mode.png)
> ![Profile Edit](screenshots/profile-edit.png)

---

## 🛠️ Tech Stack

- **Backend:** Flask (RESTful API & WebSockets via Flask-SocketIO)
- **Frontend:** HTML, CSS, JavaScript, Bootstrap, Tailwind CSS, jQuery
- **Database:** MongoDB
- **Deployment:** Docker

---

## 🚦 Getting Started

1. **Clone the repo:**
    ```bash
    git clone https://github.com/yourusername/sec-chat.git
    cd sec-chat
    ```
2. **Configure environment variables** (see `.env.example`).
3. **Build and run with Docker:**
    ```bash
    docker-compose up --build
    ```
4. **Visit** `http://localhost:5000` in your browser.

---

## 📝 TODO

- [ ] Email authentication for registration and password reset
- [ ] Move static files (profile pics, etc.) to S3 or cloud storage
- [ ] Mobile app (React Native or Flutter)
- [ ] Group chats and media sharing
- [ ] Push notifications

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

## 📄 License

MIT License

---

> **Sec Chat** — Secure, private, and beautiful messaging for everyone.
