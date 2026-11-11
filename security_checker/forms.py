"""Static checks on the <form> elements of an HTML page.

This only looks at the markup. It cannot see server-side protections
(a CSRF token stored in a header, SameSite cookies...), so a finding is
something to verify, not a proven vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser

from .findings import Finding, Severity

CSRF_FIELD_NAMES = (
    "csrf", "xsrf", "_token", "authenticity_token", "csrfmiddlewaretoken",
    "__requestverificationtoken", "nonce",
)
GOOD_PASSWORD_AUTOCOMPLETE = {"current-password", "new-password", "one-time-code"}


@dataclass
class Form:
    index: int
    attrs: dict[str, str]
    inputs: list[dict[str, str]] = field(default_factory=list)

    @property
    def method(self) -> str:
        return (self.attrs.get("method") or "get").lower()

    @property
    def action(self) -> str:
        return (self.attrs.get("action") or "").strip()

    def inputs_of_type(self, kind: str) -> list[dict[str, str]]:
        return [i for i in self.inputs if (i.get("type") or "text").lower() == kind]


class _FormCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[Form] = []
        self._current: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}
        if tag == "form":
            self._current = Form(len(self.forms) + 1, values)
            self.forms.append(self._current)
        elif tag in ("input", "textarea", "select") and self._current is not None:
            values.setdefault("type", "text" if tag == "input" else tag)
            self._current.inputs.append(values)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None


def parse_forms(html: str) -> list[Form]:
    collector = _FormCollector()
    collector.feed(html)
    collector.close()
    return collector.forms


def _has_csrf_token(form: Form) -> bool:
    for hidden in form.inputs_of_type("hidden"):
        name = hidden.get("name", "").lower()
        if any(marker in name for marker in CSRF_FIELD_NAMES) and hidden.get("value"):
            return True
    return False


def audit_form(form: Form, page_is_https: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    label = f"Form {form.index}"
    passwords = form.inputs_of_type("password")

    if passwords and form.method == "get":
        findings.append(Finding(Severity.HIGH, "password-in-get",
            f"{label}: sends a password with GET, so it ends up in the URL, browser history and server logs. Use POST."))
    elif form.method == "get" and form.inputs_of_type("email"):
        findings.append(Finding(Severity.LOW, "personal-data-in-get", f"{label}: sends an email address with GET. Prefer POST."))

    if form.action.lower().startswith("http://"):
        severity = Severity.HIGH if passwords else Severity.MEDIUM
        findings.append(Finding(severity, "insecure-action", f"{label}: action uses HTTP ({form.action}), data is sent unencrypted."))
    elif not form.action:
        findings.append(Finding(Severity.INFO, "no-action", f"{label}: no action attribute, the form is sent back to the current URL."))

    if form.method == "post" and not _has_csrf_token(form):
        findings.append(Finding(Severity.MEDIUM, "no-csrf-token",
            f"{label}: POST form without a hidden anti-CSRF token. Check that the server protects it another way."))

    for field_ in passwords:
        name = field_.get("name") or field_.get("id") or "?"
        if field_.get("value"):
            findings.append(Finding(Severity.HIGH, "prefilled-password", f"{label}: password field '{name}' has a value written in the HTML."))
        autocomplete = field_.get("autocomplete", "").lower()
        if autocomplete not in GOOD_PASSWORD_AUTOCOMPLETE:
            findings.append(Finding(Severity.LOW, "password-autocomplete",
                f"{label}: password field '{name}' should use autocomplete=\"current-password\" or \"new-password\" "
                "so password managers work correctly."))

    if passwords and not page_is_https and not form.action.lower().startswith("https://"):
        findings.append(Finding(Severity.INFO, "check-https", f"{label}: make sure this page is only served over HTTPS."))
    return findings


def audit_html(html: str, page_is_https: bool = False) -> list[Finding]:
    forms = parse_forms(html)
    if not forms:
        return [Finding(Severity.INFO, "no-form", "No <form> element was found.")]
    findings: list[Finding] = []
    for form in forms:
        findings.extend(audit_form(form, page_is_https))
    return findings
