# 🔐 VaultAI — AI-Powered Password Manager

> Enterprise-grade encrypted password vault with an AI Security Advisor powered by **Groq + Qwen-3-32B**.

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35+-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io)
[![Groq](https://img.shields.io/badge/Groq-Qwen--3--32B-f55036)](https://console.groq.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔒 AES-256-CBC Encryption | Every credential encrypted with a per-record IV |
| 🗝️ PBKDF2 Key Derivation | 600,000 iterations, NIST SP 800-132 compliant |
| 🛡️ bcrypt Authentication | 12-round cost factor for master password hashing |
| 🤖 AI Security Advisor | Qwen-3-32B via Groq — strength analysis, tips, free chat |
| 🔍 HaveIBeenPwned | k-anonymity breach detection (password never leaves client) |
| 📊 Security Dashboard | Vault-wide score, weak/reused detection, strength distribution |
| ⚡ Password Generator | CSPRNG-based, configurable, passphrase + bulk modes |
| 📋 Audit Log | Immutable security event history in SQLite |
| 📋 Auto-Clear Clipboard | Passwords clear after 30 seconds automatically |
| 🌙 Dark Mode | Professional dark UI, no setup required |

---

## 🏗️ Project Structure

```
ai_password_manager/
│
├── app.py                  ← Streamlit UI (all pages & routing)
├── config.py               ← Centralised configuration & env vars
├── database.py             ← SQLite data layer (parameterised queries)
├── encryption.py           ← AES-256-CBC + PBKDF2 key derivation
├── auth.py                 ← bcrypt auth + session management
├── password_generator.py   ← CSPRNG password & passphrase generator
├── ai_advisor.py           ← Groq + Qwen-3-32B AI integration
├── breach_checker.py       ← HaveIBeenPwned k-anonymity API
│
├── utils/
│   ├── __init__.py
│   ├── logger.py           ← JSON audit logging with sensitive masking
│   └── helpers.py          ← Strength scoring, reuse detection, scoring
│
├── .streamlit/
│   └── config.toml         ← Dark theme + server config
│
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## 🗄️ Database Schema

```sql
-- Users table: master account credentials
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,   -- bcrypt hash (never plaintext)
    salt          BLOB    NOT NULL,   -- PBKDF2 salt (32 random bytes)
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    last_login    TEXT
);

-- Credentials vault: AES-256 encrypted entries
CREATE TABLE credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    website       TEXT    NOT NULL,
    username      TEXT    NOT NULL,
    password_enc  TEXT    NOT NULL,   -- base64(IV || AES-CBC ciphertext)
    notes_enc     TEXT,               -- same format, optional
    category      TEXT    DEFAULT 'General',
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Audit log: immutable event history
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    event      TEXT    NOT NULL,      -- e.g. LOGIN_SUCCESS, CREDENTIAL_ADDED
    detail     TEXT,
    ip_hint    TEXT,
    ts         TEXT    NOT NULL DEFAULT (datetime('now'))
);
```

---

## 🔐 Security Architecture

```
Master Password
       │
       ▼
  bcrypt (12 rounds)  ──► stored in users.password_hash
       │
       ▼
  PBKDF2-HMAC-SHA256  ──► 32-byte AES Key  (in-memory ONLY, never stored)
  (600,000 iterations)
       │
       ▼
  AES-256-CBC + random IV (per credential)
       │
       ▼
  base64(IV || ciphertext)  ──► stored in credentials.password_enc
```

**Key security properties:**
- Master password → bcrypt hash (one-way, stored safely in DB)
- AES key → derived in-memory from master password + salt via PBKDF2
- AES key is **never written to disk or logs**
- Each credential gets a fresh 16-byte random IV (prevents IV-reuse attacks)
- HaveIBeenPwned uses **k-anonymity**: only first 5 chars of SHA-1 hash are sent
- All DB queries use **parameterised statements** (SQL injection prevention)
- Sensitive values are **masked in logs** via regex

---

## 🚀 Installation

### Prerequisites
- Python 3.10 or higher
- pip

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/vaultai-password-manager.git
cd vaultai-password-manager
```

### 2. Create and activate virtual environment

```bash
python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

```env
GROQ_API_KEY=your_groq_api_key_here
HIBP_API_KEY=optional_hibp_key_for_email_checks
```

**Get a free Groq API key:** https://console.groq.com

### 5. Run the application

```bash
streamlit run app.py
```

Open your browser at: **http://localhost:8501**

---

## ☁️ Deploy to Streamlit Cloud

1. Push your code to a public GitHub repository  
   *(Ensure `.env` and `vault.db` are in `.gitignore`)*

2. Go to [share.streamlit.io](https://share.streamlit.io) → **New app**

3. Set your repository, branch, and main file (`app.py`)

4. In **Advanced settings → Secrets**, add:
   ```toml
   GROQ_API_KEY = "your_groq_api_key"
   HIBP_API_KEY = "your_hibp_key"
   ```

5. Click **Deploy** — your app will be live in ~60 seconds.

> **Note:** Streamlit Cloud uses ephemeral storage. The SQLite database resets on each deployment. For persistent storage in production, replace the SQLite layer with PostgreSQL (e.g., Supabase free tier).

---

## 🖥️ UI Screenshots Description

| Page | Description |
|---|---|
| **Login** | Dark-themed two-tab card (Login / Register) with real-time master password strength meter |
| **Vault** | Searchable list of credentials with colour-coded strength bars, Weak/Reused badges, reveal/copy/AI/edit/delete actions |
| **Add Credential** | Split-panel form: credential fields on left, quick generator + breach checker on right |
| **Password Generator** | Three tabs: Random (with full options), Passphrase (word-based), Bulk (batch generation with strength labels) |
| **AI Advisor** | Four tabs: single password analysis, security tips by topic, free-chat with CipherAI, vault-wide AI analysis |
| **Security Dashboard** | 5 metric boxes (total/weak/reused/score/grade), bar charts for strength distribution & category breakdown, detailed weak/reused lists |
| **Audit Log** | Colour-coded event badges (success/error/warning) with timestamps and detail fields |

---

## 🤖 AI Integration Details

```python
from groq import Groq

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

response = client.chat.completions.create(
    model="qwen/qwen3-32b",
    messages=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": "Analyze password characteristics: length=8, no special chars..."}
    ],
    max_tokens=1024,
    temperature=0.3,
)
```

**Privacy note:** The actual password text is **never sent to the AI API**. Instead, `ai_advisor.py` extracts structural characteristics (length, character class presence, pattern detection) and sends those.

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

---

## 🔮 Future Improvements

- [ ] **PostgreSQL backend** for multi-user cloud deployments
- [ ] **TOTP / FIDO2 MFA** for enhanced login security  
- [ ] **Browser extension** for auto-fill integration
- [ ] **Encrypted vault export** (JSON + AES envelope)
- [ ] **Team vaults** with role-based access control (RBAC)
- [ ] **Password rotation reminders** with email notifications
- [ ] **Zero-knowledge architecture** (server never sees plaintext)
- [ ] **Biometric unlock** (WebAuthn / TouchID integration)
- [ ] **Dark web monitoring** — automated breach alerts
- [ ] **Mobile app** (Kivy or React Native wrapper)

---

## 📜 License

MIT — free for personal and commercial use. Attribution appreciated.

---

## 🙏 Acknowledgements

- [Groq](https://groq.com) — Ultra-fast LLM inference
- [Qwen](https://huggingface.co/Qwen) — Qwen-3-32B model by Alibaba Cloud  
- [HaveIBeenPwned](https://haveibeenpwned.com) — Troy Hunt's breach database
- [Streamlit](https://streamlit.io) — Rapid Python web apps
- [cryptography](https://cryptography.io) — Solid Python crypto primitives

---

*Built as a cybersecurity portfolio project demonstrating AES-256 encryption, secure authentication, AI integration, and production-grade Python architecture.*
