"""
auth.py — Authentication module for VaultAI.

Responsibilities:
  • Register / verify master password using bcrypt
  • Derive AES key from master password (in-memory only)
  • Session state helpers for Streamlit
  • Brute-force lockout tracking
"""

import bcrypt
import streamlit as st
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

import database as db
from encryption import derive_key, generate_salt
from config import BCRYPT_ROUNDS, SESSION_TIMEOUT_MINUTES, MAX_LOGIN_ATTEMPTS
from utils.logger import logger


# ─── Password Hashing ────────────────────────────────────────────────────────

def hash_master_password(master_password: str) -> str:
    """Hash master password with bcrypt. Returns the hash as a string."""
    return bcrypt.hashpw(
        master_password.encode("utf-8"),
        bcrypt.gensalt(rounds=BCRYPT_ROUNDS),
    ).decode("utf-8")


def verify_master_password(master_password: str, hashed: str) -> bool:
    """Constant-time bcrypt comparison."""
    return bcrypt.checkpw(
        master_password.encode("utf-8"),
        hashed.encode("utf-8"),
    )


# ─── Registration ────────────────────────────────────────────────────────────

def register_user(username: str, master_password: str) -> Tuple[bool, str]:
    """
    Create a new vault user.

    Returns:
        (True, "") on success
        (False, error_message) on failure
    """
    if db.get_user_by_username(username):
        return False, "Username already exists."

    if len(master_password) < 8:
        return False, "Master password must be at least 8 characters."

    try:
        salt = generate_salt()
        pwd_hash = hash_master_password(master_password)
        db.create_user(username, pwd_hash, salt)
        logger.info("New user registered: %s", username)
        return True, ""
    except Exception as exc:
        logger.error("Registration error: %s", exc)
        return False, "Registration failed. Please try again."


# ─── Login ────────────────────────────────────────────────────────────────────

def login_user(username: str, master_password: str) -> Tuple[bool, str]:
    """
    Authenticate user and populate st.session_state.

    Session keys set on success:
        authenticated  : bool
        user_id        : int
        username       : str
        aes_key        : bytes  (derived AES key — never persisted)
        login_time     : datetime
        failed_attempts: reset to 0
    """
    _init_session()

    # Lockout check
    if st.session_state.failed_attempts >= MAX_LOGIN_ATTEMPTS:
        return False, f"Account locked after {MAX_LOGIN_ATTEMPTS} failed attempts. Restart the app."

    user = db.get_user_by_username(username)
    if not user:
        st.session_state.failed_attempts += 1
        db.log_event(None, "LOGIN_FAILED", f"username={username} reason=user_not_found")
        return False, "Invalid credentials."

    if not verify_master_password(master_password, user["password_hash"]):
        st.session_state.failed_attempts += 1
        db.log_event(user["id"], "LOGIN_FAILED", "reason=wrong_password")
        return False, "Invalid credentials."

    # Derive AES key in-memory
    aes_key = derive_key(master_password, bytes(user["salt"]))

    # Populate session
    st.session_state.authenticated = True
    st.session_state.user_id = user["id"]
    st.session_state.username = user["username"]
    st.session_state.aes_key = aes_key
    st.session_state.login_time = datetime.now(timezone.utc)
    st.session_state.failed_attempts = 0

    db.update_last_login(user["id"])
    db.log_event(user["id"], "LOGIN_SUCCESS")
    logger.info("Login success: %s", username)
    return True, ""


# ─── Session Helpers ─────────────────────────────────────────────────────────

def _init_session() -> None:
    defaults = {
        "authenticated": False,
        "user_id": None,
        "username": None,
        "aes_key": None,
        "login_time": None,
        "failed_attempts": 0,
        "current_page": "vault",
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


def is_authenticated() -> bool:
    """Check session validity including timeout."""
    _init_session()
    if not st.session_state.authenticated:
        return False

    # Session timeout
    if st.session_state.login_time:
        elapsed = datetime.now(timezone.utc) - st.session_state.login_time
        if elapsed > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            logout_user()
            st.warning("Session expired. Please log in again.")
            return False

    return True


def logout_user() -> None:
    """Clear all session state."""
    keys_to_clear = [
        "authenticated", "user_id", "username",
        "aes_key", "login_time",
    ]
    for key in keys_to_clear:
        st.session_state[key] = None
    st.session_state.authenticated = False
    logger.info("User logged out.")


def get_aes_key() -> Optional[bytes]:
    return st.session_state.get("aes_key")


def get_user_id() -> Optional[int]:
    return st.session_state.get("user_id")


def get_username() -> Optional[str]:
    return st.session_state.get("username")
