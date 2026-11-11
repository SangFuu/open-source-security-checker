import json
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from security_checker.cli import main
from security_checker.forms import audit_html, parse_forms

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def codes(findings):
    return {f.code for f in findings}


class ParserTests(unittest.TestCase):
    def test_inputs_belong_to_their_form(self):
        forms = parse_forms('<form><input name="a"></form><input name="outside"><form><input name="b"><textarea name="c"></textarea></form>')
        self.assertEqual([[i["name"] for i in f.inputs] for f in forms], [["a"], ["b", "c"]])

    def test_no_form(self):
        self.assertEqual(codes(audit_html("<p>hello</p>")), {"no-form"})


class FormAuditTests(unittest.TestCase):
    def test_password_sent_with_get(self):
        findings = audit_html('<form action="https://x.test"><input type="password" name="pw" autocomplete="current-password"></form>')
        self.assertIn("password-in-get", codes(findings))

    def test_http_action(self):
        findings = audit_html('<form method="post" action="http://x.test/login"><input type="password" name="pw"></form>')
        self.assertIn("insecure-action", codes(findings))

    def test_csrf_token_required_on_post(self):
        without = audit_html('<form method="post" action="/save"><input name="q"></form>')
        with_token = audit_html('<form method="post" action="/save"><input type="hidden" name="csrf_token" value="abc"><input name="q"></form>')
        empty_token = audit_html('<form method="post" action="/save"><input type="hidden" name="_token" value=""></form>')
        self.assertIn("no-csrf-token", codes(without))
        self.assertNotIn("no-csrf-token", codes(with_token))
        self.assertIn("no-csrf-token", codes(empty_token))

    def test_django_and_aspnet_token_names(self):
        for name in ("csrfmiddlewaretoken", "__RequestVerificationToken", "authenticity_token"):
            html = f'<form method="post"><input type="hidden" name="{name}" value="x"></form>'
            self.assertNotIn("no-csrf-token", codes(audit_html(html)), name)

    def test_password_autocomplete(self):
        bad = audit_html('<form method="post"><input type="hidden" name="csrf" value="x"><input type="password" name="pw" autocomplete="off"></form>', page_is_https=True)
        good = audit_html('<form method="post"><input type="hidden" name="csrf" value="x"><input type="password" name="pw" autocomplete="new-password"></form>', page_is_https=True)
        self.assertIn("password-autocomplete", codes(bad))
        self.assertNotIn("password-autocomplete", codes(good))

    def test_prefilled_password(self):
        self.assertIn("prefilled-password", codes(audit_html('<form><input type="password" name="pw" value="secret"></form>')))


class ExampleFilesTests(unittest.TestCase):
    def test_insecure_example(self):
        found = codes(audit_html((EXAMPLES / "login_insecure.html").read_text()))
        self.assertTrue({"password-in-get", "insecure-action", "prefilled-password", "no-csrf-token"} <= found)

    def test_secure_example_has_no_real_issue(self):
        findings = audit_html((EXAMPLES / "login_secure.html").read_text(), page_is_https=True)
        self.assertEqual(findings, [])


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(list(args))
        return code, out.getvalue()

    def test_exit_code_reflects_high_findings(self):
        self.assertEqual(self.run_cli("form", str(EXAMPLES / "login_insecure.html"))[0], 1)
        self.assertEqual(self.run_cli("form", "--https", str(EXAMPLES / "login_secure.html"))[0], 0)

    def test_json_output(self):
        code, out = self.run_cli("--json", "password", "azerty")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data["strength"], "very weak")


if __name__ == "__main__":
    unittest.main()
