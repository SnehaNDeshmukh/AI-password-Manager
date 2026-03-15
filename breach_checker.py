"""
breach_checker.py — Password breach detection using HaveIBeenPwned API.

Uses k-anonymity model: only the first 5 characters of the SHA-1 hash
are sent to the API. The full hash NEVER leaves the client.

Reference: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
"""

import hashlib
import requests
from typing import Tuple
from utils.logger import logger


HIBP_URL = "https://api.pwnedpasswords.com/range/{prefix}"
REQUEST_TIMEOUT = 5  # seconds


def check_password_breach(password: str) -> Tuple[int, str]:
    """
    Check if a password has appeared in known data breaches.

    Algorithm (k-anonymity):
      1. SHA-1 hash the password.
      2. Send only the first 5 hex chars to HIBP API.
      3. API returns all hashes with that prefix + breach counts.
      4. Check if the remaining suffix is in the response — locally.

    Returns:
        (count, message) where count is the number of times the password
        has been seen in breaches (0 = not found).
    """
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        response = requests.get(
            HIBP_URL.format(prefix=prefix),
            headers={"Add-Padding": "true"},   # Prevents traffic analysis
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        # Parse response: each line is "HASH_SUFFIX:COUNT"
        for line in response.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0] == suffix:
                count = int(parts[1])
                msg = (
                    f"🚨 Found in {count:,} data breaches! Change this password immediately."
                    if count > 0
                    else "✅ Not found in any known breaches."
                )
                return count, msg

        return 0, "✅ Not found in any known breaches."

    except requests.exceptions.ConnectionError:
        logger.warning("HIBP API unreachable — running in offline mode.")
        return -1, "⚠️ Breach check unavailable (no internet connection)."
    except requests.exceptions.Timeout:
        logger.warning("HIBP API timed out.")
        return -1, "⚠️ Breach check timed out. Try again later."
    except requests.exceptions.HTTPError as exc:
        logger.error("HIBP API HTTP error: %s", exc)
        return -1, f"⚠️ Breach check failed: HTTP {exc.response.status_code}"
    except Exception as exc:
        logger.error("Breach check error: %s", exc)
        return -1, "⚠️ Breach check failed unexpectedly."


def check_email_breach(email: str) -> Tuple[list, str]:
    """
    Check if an email has appeared in known data breaches.
    Requires HIBP_API_KEY (paid tier).

    Returns:
        (breaches_list, message)
    """
    from config import HIBP_API_KEY
    if not HIBP_API_KEY:
        return [], "⚠️ Email breach check requires a HaveIBeenPwned API key."

    try:
        response = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={
                "hibp-api-key": HIBP_API_KEY,
                "User-Agent": "VaultAI-PasswordManager",
            },
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 404:
            return [], "✅ No breaches found for this email."
        response.raise_for_status()

        breaches = response.json()
        names = [b.get("Name", "Unknown") for b in breaches]
        msg = f"🚨 Found in {len(names)} breach(es): {', '.join(names[:5])}"
        if len(names) > 5:
            msg += f" and {len(names) - 5} more."
        return breaches, msg

    except requests.exceptions.HTTPError as exc:
        if exc.response.status_code == 401:
            return [], "⚠️ Invalid HIBP API key."
        return [], f"⚠️ Email check failed: {exc}"
    except Exception as exc:
        logger.error("Email breach check error: %s", exc)
        return [], "⚠️ Email breach check failed."


def simulate_breach_check(password: str) -> Tuple[int, str]:
    """
    Offline simulation for demo/testing when HIBP is unavailable.
    Flags obviously weak passwords as 'breached'.
    """
    COMMON_WEAK = {
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "dragon", "master", "abc123",
        "password1", "12345678", "iloveyou", "sunshine",
    }
    if password.lower() in COMMON_WEAK or len(password) < 8:
        return 99999, "🚨 [Simulated] This password is extremely common and would be found in breach databases."
    return 0, "✅ [Simulated] Password not found in simulated breach database."
