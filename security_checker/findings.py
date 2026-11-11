"""Common result type shared by the password and form checks."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    severity: Severity
    code: str
    message: str

    def to_dict(self) -> dict:
        return {"severity": str(self.severity), "code": self.code, "message": self.message}
