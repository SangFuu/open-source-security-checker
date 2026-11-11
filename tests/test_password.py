import unittest
from unittest import mock

from security_checker import password
from security_checker.password import check_password, estimate_entropy, is_common


def codes(report):
    return {f.code for f in report.findings}


class EntropyTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(estimate_entropy(""), 0)

    def test_repetition_and_sequences_count_little(self):
        self.assertLess(estimate_entropy("aaaaaaaaaaaa"), 20)
        self.assertLess(estimate_entropy("abcdefghijkl"), 20)
        self.assertLess(estimate_entropy("azertyuiop"), 20)

    def test_mixed_random_password_scores_high(self):
        self.assertGreater(estimate_entropy("T7#qLm2!vR9x"), 70)

    def test_longer_is_stronger(self):
        self.assertGreater(estimate_entropy("correct-horse-battery-staple"), estimate_entropy("horse-staple"))


class CommonPasswordTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(is_common("azerty"))

    def test_leetspeak_and_suffix_are_detected(self):
        self.assertTrue(is_common("P@ssw0rd2024!"))
        self.assertTrue(is_common("Marseille13"))

    def test_unrelated_password(self):
        self.assertFalse(is_common("T7#qLm2!vR9x"))


class CheckPasswordTests(unittest.TestCase):
    def test_weak_password(self):
        report = check_password("abc")
        self.assertEqual(report.strength, "very weak")
        self.assertIn("too-short", codes(report))

    def test_common_password_is_always_very_weak(self):
        report = check_password("Password123!")
        self.assertIn("common-password", codes(report))
        self.assertEqual(report.strength, "very weak")

    def test_strong_password(self):
        report = check_password("T7#qLm2!vR9x-Kp")
        self.assertEqual(report.findings, [])
        self.assertIn(report.strength, ("strong", "very strong"))

    def test_hibp_is_only_called_on_request(self):
        with mock.patch.object(password, "pwned_count", return_value=42) as pwned:
            self.assertNotIn("pwned", codes(check_password("T7#qLm2!vR9x-Kp")))
            pwned.assert_not_called()
            report = check_password("T7#qLm2!vR9x-Kp", use_hibp=True)
        self.assertIn("pwned", codes(report))
        self.assertEqual(report.strength, "very weak")

    def test_hibp_sends_only_hash_prefix(self):
        # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        body = b"1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n0000000000000000000000000000000000:0"
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = body
        with mock.patch("urllib.request.urlopen", return_value=response) as urlopen:
            self.assertEqual(password.pwned_count("password"), 3861493)
        url = urlopen.call_args[0][0].full_url
        self.assertTrue(url.endswith("/range/5BAA6"))


if __name__ == "__main__":
    unittest.main()
