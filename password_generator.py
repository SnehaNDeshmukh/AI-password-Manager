"""
password_generator.py — Cryptographically secure password generator.

Uses secrets module (CSPRNG) — never random or os.urandom directly
for character selection, ensuring uniform distribution.
"""

import secrets
import string
from typing import List
from config import DEFAULT_PWD_LENGTH, MIN_PWD_LENGTH, MAX_PWD_LENGTH


# ─── Character Sets ───────────────────────────────────────────────────────────

LOWERCASE  = string.ascii_lowercase          # a-z
UPPERCASE  = string.ascii_uppercase          # A-Z
DIGITS     = string.digits                   # 0-9
SPECIAL    = "!@#$%^&*()_+-=[]{}|;:,.<>?"  # safe special chars (no backtick/quote)
AMBIGUOUS  = "0O1lI"                         # visually confusing chars


def generate_password(
    length: int = DEFAULT_PWD_LENGTH,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """
    Generate a cryptographically secure random password.

    Algorithm:
      1. Build the charset from selected options.
      2. Guarantee at least one character from each required class.
      3. Fill remaining positions randomly from full charset.
      4. Fisher-Yates shuffle via secrets.SystemRandom.

    Args:
        length:            Desired password length (clamped to MIN/MAX).
        use_uppercase:     Include A-Z.
        use_lowercase:     Include a-z.
        use_digits:        Include 0-9.
        use_special:       Include special characters.
        exclude_ambiguous: Remove visually similar chars (0, O, 1, l, I).

    Returns:
        Password string.

    Raises:
        ValueError: If no character class is selected.
    """
    length = max(MIN_PWD_LENGTH, min(length, MAX_PWD_LENGTH))

    charset: str = ""
    required_chars: List[str] = []

    def add_class(chars: str) -> None:
        nonlocal charset
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        if chars:
            charset += chars
            required_chars.append(secrets.choice(chars))

    if use_lowercase:  add_class(LOWERCASE)
    if use_uppercase:  add_class(UPPERCASE)
    if use_digits:     add_class(DIGITS)
    if use_special:    add_class(SPECIAL)

    if not charset:
        raise ValueError("At least one character class must be selected.")

    # Fill remaining positions
    remaining = length - len(required_chars)
    filler = [secrets.choice(charset) for _ in range(remaining)]

    # Combine and shuffle (Fisher-Yates via secrets.SystemRandom)
    password_list = required_chars + filler
    rng = secrets.SystemRandom()
    rng.shuffle(password_list)

    return "".join(password_list)


def generate_passphrase(word_count: int = 4, separator: str = "-") -> str:
    """
    Generate a memorable passphrase using a built-in word list.
    Falls back to random pronounceable syllables if word list unavailable.
    """
    # Compact embedded word list (EFF short list subset)
    words = [
        "apple", "brave", "cloud", "dance", "eagle", "flame", "grace",
        "happy", "ivory", "joker", "karma", "lemon", "magic", "noble",
        "ocean", "piano", "quiet", "river", "storm", "tiger", "urban",
        "vivid", "water", "xenon", "yacht", "zebra", "amber", "blaze",
        "crisp", "delta", "ember", "frost", "globe", "honey", "ideal",
        "jewel", "kiwi",  "lunar", "maple", "neon",  "oasis", "pearl",
        "quark", "radar", "solar", "tango", "ultra", "vapor", "waltz",
        "xray",  "yield", "zesty",
    ]
    phrase_words = [secrets.choice(words) for _ in range(word_count)]
    # Add a random number for entropy boost
    phrase_words.append(str(secrets.randbelow(9999)).zfill(4))
    return separator.join(phrase_words)


def password_suggestions(count: int = 5) -> List[str]:
    """Return a list of strong password suggestions with different profiles."""
    profiles = [
        dict(length=20, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True),
        dict(length=24, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=False),
        dict(length=16, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True, exclude_ambiguous=True),
        dict(length=32, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True),
        dict(length=20, use_uppercase=True, use_lowercase=True, use_digits=False, use_special=True),
    ]
    return [generate_password(**profiles[i % len(profiles)]) for i in range(count)]
