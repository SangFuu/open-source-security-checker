# Open Source Security Checker

A small Python command-line tool for checking password strength and common form security issues locally.

## Features

- Checks password length, character variety and common weak patterns.
- Audits HTML forms for missing `method`, insecure `action` URLs and missing CSRF-related hints.
- Runs locally without sending data to a remote service.

## Usage

```bash
python -m src.security_checker password "A password to test"
python -m src.security_checker form examples/login.html
```

## Development

```bash
python -m unittest discover -s tests -v
```

This project is released under the MIT License.
