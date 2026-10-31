import unittest
from src.security_checker import audit_forms, check_password

class SecurityCheckerTests(unittest.TestCase):
    def test_weak_password(self):
        self.assertTrue(check_password("abc"))
    def test_strong_password(self):
        self.assertEqual(check_password("A-secure-pass-42!"), [])
    def test_form_audit(self):
        findings=audit_forms('<form method="get" action="http://example.test"></form>')
        self.assertEqual(len(findings), 2)

if __name__ == "__main__": unittest.main()
