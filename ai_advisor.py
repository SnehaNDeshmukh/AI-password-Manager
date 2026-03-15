"""
ai_advisor.py — AI Security Advisor powered by Groq + Qwen-3-32B.

Capabilities:
  • Analyze password strength with expert cybersecurity advice
  • Detect and explain security risks
  • Generate custom strong passwords on demand
  • Provide vault-wide security recommendations
  • Explain breach risks in plain language
"""

import os
from typing import Optional
from groq import Groq
from config import GROQ_API_KEY, AI_MODEL, AI_MAX_TOKENS, AI_TEMPERATURE
from utils.logger import logger


# ─── Client Factory ───────────────────────────────────────────────────────────

def _get_client() -> Optional[Groq]:
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY not set — AI Advisor disabled.")
        return None
    return Groq(api_key=GROQ_API_KEY)


# ─── System Prompt ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are CipherAI, an expert cybersecurity advisor embedded in an enterprise password manager.
Your role is to provide clear, actionable, and technically accurate security advice.

Guidelines:
- Be concise and direct — security professionals value brevity.
- Use structured markdown with headers and bullet points.
- Rate passwords on a scale: Critical / High Risk / Medium Risk / Low Risk / Secure.
- Always provide specific improvement actions, not vague advice.
- Reference real attack vectors (dictionary attacks, credential stuffing, rainbow tables) when relevant.
- Never reveal or repeat the actual password in your analysis — reference it as "[the submitted password]".
- Keep responses under 400 words unless a detailed vault analysis is requested.
"""


# ─── Core Analysis Functions ──────────────────────────────────────────────────

def analyze_password(password: str, context: str = "") -> str:
    """
    Get AI analysis of a single password.

    Args:
        password: The password to analyze (will NOT be sent to API in plaintext —
                  we send structural characteristics instead).
        context:  Optional context (e.g., website the password is used for).

    Returns:
        Markdown-formatted analysis string.
    """
    client = _get_client()
    if not client:
        return "⚠️ AI Advisor unavailable. Set GROQ_API_KEY in your .env file."

    # Security: describe password characteristics, not the password itself
    char_desc = _describe_password(password)

    prompt = f"""Analyze the security of a password with these characteristics:
{char_desc}
{"Context: " + context if context else ""}

Provide:
1. **Risk Level** (Critical / High / Medium / Low / Secure)
2. **Strength Analysis** — what makes it weak or strong
3. **Attack Vectors** — which attacks could compromise it
4. **Time-to-Crack Estimate** — rough estimate for modern hardware
5. **Improvement Recommendations** — 3 specific, actionable steps
6. **Replacement Suggestion** — describe the ideal replacement (don't generate one — let the password generator do that)
"""
    return _chat(prompt)


def get_security_tips(topic: str = "general") -> str:
    """Return cybersecurity best-practice tips for a given topic."""
    client = _get_client()
    if not client:
        return "⚠️ AI Advisor unavailable."

    prompts = {
        "general": "Give me 5 enterprise-grade password security best practices with brief explanations.",
        "phishing": "Explain phishing attacks targeting password managers and how to defend against them.",
        "mfa": "Explain multi-factor authentication types (TOTP, FIDO2, SMS) and which are most secure for enterprises.",
        "breach": "Explain what happens when passwords are breached and the steps to take immediately after a data breach.",
        "vault": "Best practices for managing a corporate password vault — sharing, rotation, and access control.",
    }

    prompt = prompts.get(topic, prompts["general"])
    return _chat(prompt)


def analyze_vault_security(stats: dict) -> str:
    """
    Get AI recommendations based on vault-wide security statistics.

    Args:
        stats: dict with keys: total, weak, reused, avg_strength, score, grade
    """
    client = _get_client()
    if not client:
        return "⚠️ AI Advisor unavailable."

    prompt = f"""Analyze this password vault security report and provide recommendations:

Vault Statistics:
- Total credentials: {stats.get('total', 0)}
- Weak passwords (score < 50): {stats.get('weak', 0)}
- Reused passwords: {stats.get('reused', 0)}
- Average password strength: {stats.get('avg_strength', 0)}/100
- Overall security score: {stats.get('score', 0)}/100 (Grade: {stats.get('grade', 'N/A')})

Provide:
1. **Overall Assessment** — 2-3 sentence executive summary
2. **Critical Issues** — prioritised list of problems to fix immediately
3. **Action Plan** — step-by-step remediation with timeline estimates
4. **Security Posture** — how this compares to enterprise security standards (NIST, CIS)
"""
    return _chat(prompt)


def explain_breach_risk(password_hash_count: int, website: str = "") -> str:
    """Explain breach risk in plain language based on HIBP result."""
    client = _get_client()
    if not client:
        return "⚠️ AI Advisor unavailable."

    if password_hash_count == 0:
        prompt = f"A password {'for ' + website if website else ''} was NOT found in any known data breach database. Explain what this means and whether the user can feel safe."
    else:
        prompt = f"A password {'for ' + website if website else ''} appears {password_hash_count:,} times in known data breach databases. Explain the risk in plain language, what attackers can do with this information, and the exact steps the user must take right now."

    return _chat(prompt)


def chat_with_advisor(user_message: str, conversation_history: list) -> str:
    """
    Free-form chat with the security advisor.

    Args:
        user_message: User's question
        conversation_history: List of {"role": ..., "content": ...} dicts

    Returns:
        Assistant response string
    """
    client = _get_client()
    if not client:
        return "⚠️ AI Advisor unavailable. Please set GROQ_API_KEY."

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(conversation_history[-8:])  # Keep last 8 turns for context
    messages.append({"role": "user", "content": user_message})

    try:
        response = client.chat.completions.create(
            model=AI_MODEL,
            messages=messages,
            max_tokens=AI_MAX_TOKENS,
            temperature=AI_TEMPERATURE,
        )
        return response.choices[0].message.content
    except Exception as exc:
        logger.error("Groq API error in chat: %s", exc)
        return f"❌ AI service error: {exc}"


# ─── Private Helpers ──────────────────────────────────────────────────────────

def _chat(prompt: str) -> str:
    """Single-turn chat completion."""
    client = _get_client()
    if not client:
        return "⚠️ AI Advisor unavailable."
    try:
        response = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            max_tokens=AI_MAX_TOKENS,
            temperature=AI_TEMPERATURE,
        )
        return response.choices[0].message.content
    except Exception as exc:
        logger.error("Groq API error: %s", exc)
        return f"❌ AI service error: {exc}"


def _describe_password(password: str) -> str:
    """Describe password characteristics without sending the actual password."""
    import re
    lines = [
        f"- Length: {len(password)} characters",
        f"- Contains uppercase: {'Yes' if re.search(r'[A-Z]', password) else 'No'}",
        f"- Contains lowercase: {'Yes' if re.search(r'[a-z]', password) else 'No'}",
        f"- Contains digits: {'Yes' if re.search(r'[0-9]', password) else 'No'}",
        f"- Contains special chars: {'Yes' if re.search(r'[^A-Za-z0-9]', password) else 'No'}",
        f"- Unique character count: {len(set(password))} / {len(password)}",
        f"- Has sequential patterns: {'Yes' if _has_sequences(password) else 'No'}",
        f"- Has keyboard walk patterns: {'Yes' if _has_keyboard_walk(password) else 'No'}",
        f"- Has repeated chars: {'Yes' if _has_repeats(password) else 'No'}",
    ]
    return "\n".join(lines)


def _has_sequences(s: str) -> bool:
    for i in range(len(s) - 3):
        if ord(s[i+1]) - ord(s[i]) == 1 and ord(s[i+2]) - ord(s[i+1]) == 1:
            return True
    return False


def _has_keyboard_walk(s: str) -> bool:
    rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
    sl = s.lower()
    for row in rows:
        for i in range(len(row) - 2):
            if row[i:i+3] in sl:
                return True
    return False


def _has_repeats(s: str) -> bool:
    for i in range(len(s) - 2):
        if s[i] == s[i+1] == s[i+2]:
            return True
    return False
