"""Local checks for password strength and HTML form security."""

from .findings import Finding, Severity
from .forms import audit_html
from .password import check_password, estimate_entropy

__all__ = ["Finding", "Severity", "audit_html", "check_password", "estimate_entropy"]
__version__ = "0.2.0"
