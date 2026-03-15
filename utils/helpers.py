"""
utils/helpers.py — Shared utility helpers: input validation,
password strength scoring, clipboard management, etc.
"""

import re
import math
import string
from typing import Tuple


# ─── Input Validation ─────────────────────────────────────────────────────────

def validate_url(url: str) -> bool:
    """Basic URL / domain validator to prevent injection via website field."""
    pattern = r"^(https?://)?([\w\-]+\.)+[\w\-]{2,}(/.*)?$"
    return bool(re.match(pattern, url.strip())) if url else False


def sanitize_text(value: str, max_len: int = 256) -> str:
    """Strip leading/trailing whitespace and limit length."""
    return value.strip()[:max_len]


def validate_username(username: str) -> Tuple[bool, str]:
    if not username:
        return False, "Username cannot be empty."
    if len(username) > 128:
        return False, "Username too long (max 128 chars)."
    return True, ""


# ─── Password Strength Scorer ─────────────────────────────────────────────────

def entropy_bits(password: str) -> float:
    """Calculate Shannon entropy in bits."""
    if not password:
        return 0.0
    freq = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(password)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def password_strength(password: str) -> dict:
    """
    Score a password from 0–100 and return a structured dict.

    Returns:
        {
            "score": int,           # 0–100
            "label": str,           # Very Weak / Weak / Fair / Strong / Very Strong
            "entropy": float,
            "checks": dict,         # individual check results
            "color": str,           # hex for UI meter
        }
    """
    checks = {
        "length_8":   len(password) >= 8,
        "length_12":  len(password) >= 12,
        "length_16":  len(password) >= 16,
        "uppercase":  bool(re.search(r"[A-Z]", password)),
        "lowercase":  bool(re.search(r"[a-z]", password)),
        "digits":     bool(re.search(r"\d", password)),
        "special":    bool(re.search(r"[^A-Za-z0-9]", password)),
        "no_common":  not _is_common_pattern(password),
    }

    score = 0
    score += 10 if checks["length_8"]   else 0
    score += 10 if checks["length_12"]  else 0
    score += 10 if checks["length_16"]  else 0
    score += 15 if checks["uppercase"]  else 0
    score += 15 if checks["lowercase"]  else 0
    score += 15 if checks["digits"]     else 0
    score += 20 if checks["special"]    else 0
    score += 5  if checks["no_common"]  else 0

    entropy = entropy_bits(password)
    # Bonus for high entropy
    if entropy > 4.0:
        score = min(100, score + 10)

    if score <= 20:
        label, color = "Very Weak",   "#ef4444"
    elif score <= 40:
        label, color = "Weak",        "#f97316"
    elif score <= 60:
        label, color = "Fair",        "#eab308"
    elif score <= 80:
        label, color = "Strong",      "#22c55e"
    else:
        label, color = "Very Strong", "#06b6d4"

    return {
        "score": score,
        "label": label,
        "entropy": round(entropy, 2),
        "checks": checks,
        "color": color,
    }


def _is_common_pattern(password: str) -> bool:
    """Detect trivially guessable patterns."""
    lower = password.lower()
    common = [
        "password", "123456", "qwerty", "abc123", "letmein",
        "admin", "welcome", "monkey", "dragon", "master",
    ]
    if any(c in lower for c in common):
        return True
    # Detect sequences like 'abcde' or '12345'
    if len(password) >= 5:
        seq = 0
        for i in range(1, len(password)):
            if ord(password[i]) - ord(password[i - 1]) == 1:
                seq += 1
                if seq >= 4:
                    return True
            else:
                seq = 0
    return False


# ─── Duplicate Detection ──────────────────────────────────────────────────────

def find_reused_passwords(credentials: list[dict]) -> dict[str, list[str]]:
    """
    Given a list of {'website': ..., 'password': ...} dicts,
    return a mapping of password → list of websites using it.
    Only entries with 2+ uses are returned.
    """
    pwd_map: dict[str, list[str]] = {}
    for cred in credentials:
        pwd = cred.get("password", "")
        site = cred.get("website", "unknown")
        if pwd:
            pwd_map.setdefault(pwd, []).append(site)
    return {k: v for k, v in pwd_map.items() if len(v) > 1}


# ─── Security Score ───────────────────────────────────────────────────────────

def compute_security_score(credentials: list[dict]) -> dict:
    """
    Compute an overall vault security score.

    Returns dict with score (0-100), breakdown, and recommendations.
    """
    if not credentials:
        return {"score": 100, "grade": "A", "breakdown": {}, "recommendations": []}

    total = len(credentials)
    strength_scores = [password_strength(c.get("password", ""))["score"] for c in credentials]
    avg_strength = sum(strength_scores) / total
    weak_count = sum(1 for s in strength_scores if s < 50)
    reused = find_reused_passwords(credentials)
    reused_count = sum(len(v) for v in reused.values())

    # Weighted score
    strength_component = avg_strength * 0.6
    reuse_penalty = min(40, (reused_count / total) * 40)
    weak_penalty = min(30, (weak_count / total) * 30)

    score = max(0, round(strength_component - reuse_penalty - weak_penalty))

    if score >= 90:   grade = "A+"
    elif score >= 80: grade = "A"
    elif score >= 70: grade = "B"
    elif score >= 60: grade = "C"
    elif score >= 50: grade = "D"
    else:             grade = "F"

    recommendations = []
    if weak_count:
        recommendations.append(f"Strengthen {weak_count} weak password(s).")
    if reused_count:
        recommendations.append(f"{reused_count} credential(s) share passwords — change them.")
    if avg_strength < 70:
        recommendations.append("Use the Password Generator to create stronger passwords.")

    return {
        "score": score,
        "grade": grade,
        "breakdown": {
            "total": total,
            "weak": weak_count,
            "reused": reused_count,
            "avg_strength": round(avg_strength, 1),
        },
        "recommendations": recommendations,
    }
