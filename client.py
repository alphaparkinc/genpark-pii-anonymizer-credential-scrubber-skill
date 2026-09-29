"""PII & Credential Token Scrubber Engine.
100% Python Standard Library.
"""

import re

class PIICredentialScrubber:
    """Scrubber engine for redacting emails, phone numbers, SSNs, and API keys."""
    PATTERNS = {
        "EMAIL": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b',
        "PHONE": r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
        "API_KEY": r'\b(ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{48}|AKIA[0-9A-Z]{16})\b',
        "IPV4": r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    }

    @classmethod
    def scrub(cls, text):
        redacted = text
        findings = []
        for pii_type, pat in cls.PATTERNS.items():
            for match in re.finditer(pat, redacted):
                val = match.group(0)
                findings.append({"type": pii_type, "value": val[:4] + "***"})
            redacted = re.sub(pat, f"[REDACTED_{pii_type}]", redacted)
        return {"scrubbed_text": redacted, "findings": findings}
