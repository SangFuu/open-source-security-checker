# Open Source Security Checker

[![tests](https://github.com/SangFuu/open-source-security-checker/actions/workflows/tests.yml/badge.svg)](https://github.com/SangFuu/open-source-security-checker/actions/workflows/tests.yml)

A small Python command-line tool that checks password strength and looks for common mistakes in HTML login forms. No dependency, Python 3.10+.

## Password check

```console
$ python -m security_checker password
Password to check (hidden):
Length: 14  |  Entropy: ~80.8 bits  |  Strength: very weak
  [HIGH  ] This password (or its base word) is in the list of very common passwords.
```

What it looks at:

- **Entropy estimate**: each character is worth `log2(pool size)` bits, except characters that repeat or follow a sequence (`aaaa`, `1234`, `azerty`), which are worth 1 bit.
- **Common passwords**: an offline list of about 200 very common passwords. The check undoes simple tricks first, so `P@ssw0rd2024!` and `Marseille13` are caught.
- **Length** (12 characters minimum) and character variety.
- **Have I Been Pwned** with `--hibp` (opt-in). Only the first 5 characters of the SHA-1 hash are sent ([k-anonymity](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange)), never the password itself.

If the password is not given as an argument it is asked with a hidden prompt, so it does not end up in the shell history.

## Form check

```console
$ python -m security_checker form examples/login_insecure.html
examples/login_insecure.html
  [HIGH  ] Form 1: sends a password with GET, so it ends up in the URL, browser history and server logs. Use POST.
  [HIGH  ] Form 1: action uses HTTP (http://example.test/login), data is sent unencrypted.
  [HIGH  ] Form 1: password field 'password' has a value written in the HTML.
  [MEDIUM] Form 2: POST form without a hidden anti-CSRF token. Check that the server protects it another way.
  [LOW   ] Form 1: password field 'password' should use autocomplete="current-password" or "new-password" ...
```

| Code | Severity | Problem |
|---|---|---|
| `password-in-get` | high | password field in a GET form |
| `insecure-action` | high / medium | form posted to an `http://` URL |
| `prefilled-password` | high | password `value` written in the HTML |
| `no-csrf-token` | medium | POST form without a non-empty hidden token (`csrf`, `_token`, `csrfmiddlewaretoken`, `__RequestVerificationToken`...) |
| `password-autocomplete` | low | missing `autocomplete="current-password"` / `"new-password"` |
| `personal-data-in-get` | low | email sent with GET |

`examples/` contains an insecure and a fixed version of the same login page.

## Options

- `--json`: machine-readable output.
- `--fail-on {info,low,medium,high}`: exit code 1 when a finding reaches this level (default `high`), which makes it usable in a CI job.
- `form --https`: the page is served over HTTPS.

## Limits

This is a static check. It does not see server-side protections (CSRF token in a header, `SameSite` cookies, HSTS), so a finding is something to verify, not a proven vulnerability. The entropy estimate does not know dictionary words: `Tr0ub4dor&3` gets a good score but is found by `--hibp`.

## Install and test

```sh
pip install .          # adds a `security-checker` command
python -m unittest discover -s tests -t . -v
```

MIT License.
