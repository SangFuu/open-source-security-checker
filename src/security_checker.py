"""Local checks for password and HTML form security."""
from __future__ import annotations
import argparse, re
from html.parser import HTMLParser

COMMON = {"password", "password123", "123456", "qwerty", "azerty", "admin"}

def check_password(value: str) -> list[str]:
    issues=[]
    if len(value) < 12: issues.append("Use at least 12 characters.")
    if value.lower() in COMMON: issues.append("This password is commonly used.")
    if not re.search(r"[a-z]", value): issues.append("Add a lowercase letter.")
    if not re.search(r"[A-Z]", value): issues.append("Add an uppercase letter.")
    if not re.search(r"\d", value): issues.append("Add a digit.")
    if not re.search(r"[^A-Za-z0-9]", value): issues.append("Add a special character.")
    return issues

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.forms=[]
    def handle_starttag(self, tag, attrs):
        if tag == "form": self.forms.append(dict(attrs))

def audit_forms(html: str) -> list[str]:
    parser=FormParser(); parser.feed(html); issues=[]
    if not parser.forms: return ["No form element was found."]
    for i, form in enumerate(parser.forms, 1):
        method=form.get("method", "get").lower()
        action=form.get("action", "")
        if method == "get": issues.append(f"Form {i}: consider POST for sensitive data.")
        if action.startswith("http://"): issues.append(f"Form {i}: action uses HTTP instead of HTTPS.")
        if not action: issues.append(f"Form {i}: action is missing; review server-side handling.")
    return issues

def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="command", required=True)
    p=sub.add_parser("password"); p.add_argument("value")
    f=sub.add_parser("form"); f.add_argument("path")
    args=parser.parse_args()
    issues = check_password(args.value) if args.command == "password" else audit_forms(open(args.path, encoding="utf-8").read())
    if issues:
        print("Findings:"); print("\n".join(f"- {x}" for x in issues))
    else: print("No basic issues found by these checks.")

if __name__ == "__main__": main()
