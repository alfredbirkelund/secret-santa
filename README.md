# 🎄 Zero-Knowledge Secret Santa

> A client-side encrypted Secret Santa draw hosted for free on GitHub Pages. Nobody — not even the organizer or programmer — knows who got whom.

---

## 🔒 How Zero-Knowledge Works

In traditional online Secret Santa apps, the database or organizer can inspect who drew whom. This implementation uses **Client-Side AES-GCM Encryption** with keys embedded strictly in the **URL hash fragment (`#...`)**.

```
  [Organizer generates draw]
        │
        ├─► Sattolo's Algorithm (O(N) uniform cycle derangement)
        ├─► AES-GCM 128-bit key generated per participant
        └─► Recipient name + budget encrypted locally
        │
        ▼
  Distribution Link: https://alfredbirkelund.github.io/secret-santa/#<payload>.<key>
        │
        │  * The hash fragment (#...) is NEVER sent to GitHub's servers over HTTP!
        │  * The organizer copies the link for "Alice" without knowing what is inside.
        │
        ▼
  [Alice opens link at home]
        │
        └─► Browser executes Web Crypto API locally in memory
        └─► Card unlocks: "You are the Secret Santa for: Bob 🎁"
```

1. **Cycle Derangement:** Everyone gives to exactly one person, receives from exactly one person, no one draws themselves, and no disjoint sub-loops are formed ($A \to B \to C \dots \to A$).
2. **Local Cryptography:** All encryption and decryption uses standard **AES-GCM (128-bit)** via Python's `cryptography` library or the browser's native `window.crypto.subtle`.
3. **HTTP Fragment Isolation:** RFC 3986 dictates that the fragment (`#...`) is handled purely on the client. It is never included in HTTP requests, server logs, or intermediate proxies.

---

## 🚀 Quick Start

### Option A: Use the Web Interface

1. Open your live GitHub Pages link (e.g. `https://alfredbirkelund.github.io/secret-santa/`).
2. Paste the list of participants (one per line).
3. *(Optional)* Add exclusions (e.g. `Alice:Bob` so partners don't draw each other), budget, or event date.
4. Click **"Generate Secret Links 🎲"**.
5. Copy the individual links and send each one privately to the respective participant via Discord, WhatsApp, Messenger, SMS, etc.

### Option B: Use the Python CLI

Generate links directly from your terminal using [`uv`](https://github.com/astral-sh/uv):

```bash
uv run generate_draw.py \
  --names "Alice,Bob,Charlie,David,Emma,Frank,Grace,Henry,Isabella" \
  --budget "200 DKK" \
  --note "Exchange on Dec 24 at Grandma's" \
  --exclude "Alice:Bob" \
  --exclude "Charlie:David" \
  --base-url "https://alfredbirkelund.github.io/secret-santa"
```

**Output:**
```
====================================================================
🎄 SECRET SANTA DISTRIBUTION LINKS (ZERO-KNOWLEDGE)
====================================================================
Send each participant their private link below.
DO NOT OPEN THEM YOURSELF — the recipient is known ONLY to their link!
--------------------------------------------------------------------
Alice      : https://alfredbirkelund.github.io/secret-santa/#7Qj...key...
Bob        : https://alfredbirkelund.github.io/secret-santa/#vP4...key...
Charlie    : https://alfredbirkelund.github.io/secret-santa/#3kX...key...
...
====================================================================
```

*Note: The CLI sorts links alphabetically by giver, completely destroying the cycle order so you cannot infer who gave to whom.*

---

## 🎁 Participant Experience

When a participant opens their link:
1. They see: *"Hi [Giver]! Recipient for [Giver] is sealed inside."*
2. An interactive, tactile holiday gift package with a **"Tap to Unwrap 🎁"** button.
3. Upon tapping:
   - Festive celebratory confetti shower.
   - Reveals the recipient's name in bold festive styling.
   - Shows event budget & notes if configured.
   - **"Copy Name"** button for easy saving.
   - **"Hide Again"** toggle in case someone walks by or is looking over their shoulder.

---

## ⚙️ Deploying on GitHub Pages

1. Create a GitHub repository (e.g., `secret-santa`).
2. Push this directory to the repository:
   ```bash
   git init
   git add .
   git commit -m "feat: zero-knowledge secret santa on github pages"
   git branch -M main
   git remote add origin https://github.com/<your-username>/secret-santa.git
   git push -u origin main
   ```
3. Enable GitHub Pages:
   - Go to your repo **Settings** > **Pages**.
   - Under **Build and deployment** > **Source**, choose **GitHub Actions** (the included `.github/workflows/deploy.yml` will deploy automatically on push) or **Deploy from a branch** (`main` / root `/`).
4. Your site is live at: `https://<your-username>.github.io/secret-santa/`!

---

## 📜 License

MIT License. Feel free to use, modify, and host for your friends and family!
