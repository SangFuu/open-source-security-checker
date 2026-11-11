"""Password strength checks.

The entropy estimate is deliberately simple: each character is worth
log2(pool size) bits, except characters that only repeat or continue a
sequence ("aaaa", "1234", "qwer"), which are worth one bit. It is not a
replacement for a full estimator like zxcvbn, but it catches the usual
mistakes and is easy to explain.
"""

from __future__ import annotations

import hashlib
import math
import string
import urllib.request
from dataclasses import dataclass, field
from importlib import resources

from .findings import Finding, Severity

KEYBOARD_ROWS = ("azertyuiop", "qsdfghjklm", "wxcvbn", "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
MIN_LENGTH = 12
HIBP_URL = "https://api.pwnedpasswords.com/range/"


def load_common_passwords() -> frozenset[str]:
    text = resources.files("security_checker.data").joinpath("common_passwords.txt").read_text(encoding="utf-8")
    return frozenset(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#"))


COMMON_PASSWORDS = load_common_passwords()


def pool_size(value: str) -> int:
    pool = 0
    if any(c in string.ascii_lowercase for c in value):
        pool += 26
    if any(c in string.ascii_uppercase for c in value):
        pool += 26
    if any(c in string.digits for c in value):
        pool += 10
    if any(not c.isalnum() for c in value):
        pool += 33
    return pool


def _continues_pattern(prev: str, cur: str) -> bool:
    if prev == cur:
        return True
    if abs(ord(prev.lower()) - ord(cur.lower())) == 1:
        return True
    pair = (prev + cur).lower()
    return any(pair in row or pair in row[::-1] for row in KEYBOARD_ROWS)


def estimate_entropy(value: str) -> float:
    if not value:
        return 0.0
    bits_per_char = math.log2(pool_size(value))
    bits = bits_per_char
    for prev, cur in zip(value, value[1:]):
        bits += 1 if _continues_pattern(prev, cur) else bits_per_char
    return round(bits, 1)


def strength_label(bits: float) -> str:
    if bits < 28:
        return "very weak"
    if bits < 36:
        return "weak"
    if bits < 60:
        return "fair"
    if bits < 80:
        return "strong"
    return "very strong"


def _base_word(value: str) -> str:
    """Lowercase, undo leetspeak and drop trailing digits/symbols: 'P@ssw0rd2024!' -> 'password'."""
    word = value.lower()
    word = word.rstrip(string.digits + string.punctuation) or word
    return word.translate(LEET)


def is_common(value: str) -> bool:
    return value.lower() in COMMON_PASSWORDS or _base_word(value) in COMMON_PASSWORDS


def pwned_count(value: str, timeout: float = 5.0) -> int:
    """Ask Have I Been Pwned how many times this password appears in known breaches.

    Only the first 5 characters of the SHA-1 hash leave the machine (k-anonymity).
    """
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    request = urllib.request.Request(HIBP_URL + prefix, headers={"Add-Padding": "true", "User-Agent": "open-source-security-checker"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        for line in response.read().decode("ascii").splitlines():
            candidate, _, count = line.partition(":")
            if candidate == suffix:
                return int(count)
    return 0


@dataclass
class PasswordReport:
    length: int
    entropy_bits: float
    strength: str
    findings: list[Finding] = field(default_factory=list)


def check_password(value: str, use_hibp: bool = False) -> PasswordReport:
    findings: list[Finding] = []
    bits = estimate_entropy(value)

    if is_common(value):
        findings.append(Finding(Severity.HIGH, "common-password", "This password (or its base word) is in the list of very common passwords."))
    if len(value) < MIN_LENGTH:
        findings.append(Finding(Severity.MEDIUM, "too-short", f"Use at least {MIN_LENGTH} characters (currently {len(value)})."))
    if value and pool_size(value) <= 26:
        findings.append(Finding(Severity.LOW, "single-charset", "Only one kind of character is used; mix letters, digits and symbols, or use a longer passphrase."))
    if bits < 36:
        findings.append(Finding(Severity.MEDIUM, "low-entropy", f"Estimated entropy is only {bits} bits."))

    if use_hibp:
        count = pwned_count(value)
        if count:
            findings.append(Finding(Severity.HIGH, "pwned", f"This password appears {count} times in known data breaches (Have I Been Pwned)."))

    if any(f.code in ("common-password", "pwned") for f in findings):
        strength = "very weak"
    else:
        strength = strength_label(bits)
    return PasswordReport(len(value), bits, strength, findings)
