"""
config.py — Central configuration for AI Password Manager
All secrets loaded from environment variables for production safety.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ─── API Keys ───────────────────────────────────────────────────────────────
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
HIBP_API_KEY: str = os.getenv("HIBP_API_KEY", "")   # HaveIBeenPwned API key

# ─── AI Model ────────────────────────────────────────────────────────────────
AI_MODEL: str = "qwen/qwen3-32b"
AI_MAX_TOKENS: int = 1024
AI_TEMPERATURE: float = 0.3

# ─── Database ────────────────────────────────────────────────────────────────
DB_PATH: str = os.getenv("DB_PATH", "vault.db")

# ─── Encryption ──────────────────────────────────────────────────────────────
PBKDF2_ITERATIONS: int = 600_000   # NIST-recommended minimum 2023
PBKDF2_HASH: str = "sha256"
AES_KEY_LENGTH: int = 32           # 256-bit key
SALT_LENGTH: int = 32              # bytes
IV_LENGTH: int = 16                # AES-CBC IV

# ─── Auth ─────────────────────────────────────────────────────────────────────
BCRYPT_ROUNDS: int = 12
SESSION_TIMEOUT_MINUTES: int = 30

# ─── Security ─────────────────────────────────────────────────────────────────
CLIPBOARD_CLEAR_SECONDS: int = 30
MAX_LOGIN_ATTEMPTS: int = 5

# ─── Password Generator Defaults ──────────────────────────────────────────────
DEFAULT_PWD_LENGTH: int = 20
MIN_PWD_LENGTH: int = 8
MAX_PWD_LENGTH: int = 128

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_FILE: str = os.getenv("LOG_FILE", "audit.log")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

# ─── UI ───────────────────────────────────────────────────────────────────────
APP_TITLE: str = "VaultAI — Secure Password Manager"
APP_ICON: str = "🔐"
