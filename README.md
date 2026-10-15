# Black Ink Network (BIN)

This is a project I was working on for a few weeks cause i was bored lmaooo; it's basically a website with encryption and messaging. I put example endpoints and photos and videos in the admin account (`User: YourLocalHomeInvader` | `Password: Bubba138#` | `Vault: Bubba138#`). I figure that someone might like this, or they are practicing breaking into shit lmao; it's not the best, but it's something lmaoo. I will not be updating this anymore. what ever they stuff said under this is AI gen explaining what it does.

---

## 🚀 What It Does

**Black Ink Network (BIN)** is a secure, self-hosted web command center built with a PHP backend and a modern Tailwind CSS frontend. It mimics a dark-themed secure server dashboard equipped with client-side encryption, encrypted file storage, and real-time communication tools. 

Key features include:
* **AES-GCM Client-Side Encryption:** All files, media attachments, and messages are encrypted and decrypted directly in the browser using the Web Crypto API (`PBKDF2` key derivation and `AES-GCM` cipher blocks) before hitting the server.
* **Encrypted Account Vault (`vault.html`):** A protected personal file manager and media gallery where users can upload, view, and organize encrypted files protected by a separate vault passphrase.
* **Communications Hub (`messages.html`):** 
  * Real-time encrypted group chat (General channel) and Direct Messages.
  * Encrypted file and media sharing directly inside chats with inline decryption previews.
  * Official read-only **Rules & Guidelines** channel.
* **Network Endpoints & Status Pings:** A dashboard displaying live status pings for various local and external services/endpoints with a built-in search filter.
* **Administrative Controls & Moderation:** 
  * Features an admin role (`YourLocalHomeInvader`) with capabilities to inspect DM transcripts, monitor a user reports queue, and issue IP or account bans.

---

## 🛠️ Project Structure

* `index.html` — Main command dashboard and active endpoints display.
* `messages.html` — Communications hub for global chat, DMs, and encrypted attachments.
* `vault.html` — Dedicated secure storage vault interface for files and media.
* `api.php` — Backend API controller handling authentication, secure file uploads/storage, messages, and admin moderation logging.
