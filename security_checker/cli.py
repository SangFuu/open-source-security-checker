"""Command-line interface: `python -m security_checker password|form ...`."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .findings import Finding, Severity
from .forms import audit_html
from .password import check_password


def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("No issue found by these checks.")
        return
    for f in sorted(findings, key=lambda f: f.severity, reverse=True):
        print(f"  [{str(f.severity).upper():6}] {f.message}")


def _exit_code(findings: list[Finding], fail_on: str) -> int:
    threshold = Severity[fail_on.upper()]
    return 1 if any(f.severity >= threshold for f in findings) else 0


def cmd_password(args: argparse.Namespace) -> int:
    value = args.value if args.value is not None else getpass.getpass("Password to check (hidden): ")
    report = check_password(value, use_hibp=args.hibp)
    if args.json:
        print(json.dumps({
            "length": report.length,
            "entropy_bits": report.entropy_bits,
            "strength": report.strength,
            "findings": [f.to_dict() for f in report.findings],
        }, indent=2))
    else:
        print(f"Length: {report.length}  |  Entropy: ~{report.entropy_bits} bits  |  Strength: {report.strength}")
        _print_findings(report.findings)
    return _exit_code(report.findings, args.fail_on)


def cmd_form(args: argparse.Namespace) -> int:
    all_findings: list[Finding] = []
    results = {}
    for path in args.paths:
        findings = audit_html(Path(path).read_text(encoding="utf-8", errors="replace"), page_is_https=args.https)
        all_findings.extend(findings)
        results[path] = [f.to_dict() for f in findings]
        if not args.json:
            print(path)
            _print_findings(findings)
    if args.json:
        print(json.dumps(results, indent=2))
    return _exit_code(all_findings, args.fail_on)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security_checker", description="Local checks for password strength and HTML form security.")
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    parser.add_argument("--fail-on", default="high", choices=["info", "low", "medium", "high"],
                        help="exit with code 1 if a finding of this severity or higher is found (default: high)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("password", help="check a password")
    p.add_argument("value", nargs="?", help="password to check (asked interactively if omitted, which keeps it out of shell history)")
    p.add_argument("--hibp", action="store_true", help="also check Have I Been Pwned (only a 5-character hash prefix is sent)")
    p.set_defaults(func=cmd_password)

    f = sub.add_parser("form", help="audit the forms of one or more HTML files")
    f.add_argument("paths", nargs="+", help="HTML files")
    f.add_argument("--https", action="store_true", help="the page is served over HTTPS")
    f.set_defaults(func=cmd_form)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
