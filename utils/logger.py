"""
utils/logger.py — Structured audit logging for security events.
All sensitive values are masked before writing to log.
"""

import logging
import os
import json
import re
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from config import LOG_FILE, LOG_LEVEL


# ─── Custom Formatter ─────────────────────────────────────────────────────────

class AuditFormatter(logging.Formatter):
    """JSON-structured log records for SIEM compatibility."""

    SENSITIVE_PATTERNS = [
        r"password['\"]?\s*[:=]\s*['\"]?[^\s,'\"\]]+",
        r"key['\"]?\s*[:=]\s*['\"]?[^\s,'\"\]]+",
        r"token['\"]?\s*[:=]\s*['\"]?[^\s,'\"\]]+",
    ]

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        message = self._mask_sensitive(message)
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "event": message,
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)

    def _mask_sensitive(self, text: str) -> str:
        for pattern in self.SENSITIVE_PATTERNS:
            text = re.sub(pattern, "[REDACTED]", text, flags=re.IGNORECASE)
        return text


# ─── Logger Factory ───────────────────────────────────────────────────────────

def get_logger(name: str = "vault_ai") -> logging.Logger:
    """Return a configured logger with rotating file + console handlers."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured

    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(level)

    # Rotating file handler — max 5 MB × 3 backups
    fh = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3)
    fh.setFormatter(AuditFormatter())
    logger.addHandler(fh)

    # Console handler (plain text for dev)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s"))
    logger.addHandler(ch)

    return logger


# Module-level convenience logger
logger = get_logger()
