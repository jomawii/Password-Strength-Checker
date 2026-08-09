"""
Unit tests for password_checker.py

Run with:
    python3 -m unittest test_password_checker.py -v
"""

import unittest
from unittest.mock import patch

import password_checker as pc


class TestNormalizeLeetspeak(unittest.TestCase):
    def test_common_substitutions(self):
        self.assertEqual(pc.normalize_leetspeak("P@ssw0rd"), "password")
        self.assertEqual(pc.normalize_leetspeak("l3tm31n"), "letmein")

    def test_no_substitutions_needed(self):
        self.assertEqual(pc.normalize_leetspeak("hello"), "hello")


class TestDetectPatterns(unittest.TestCase):
    def test_repeated_characters(self):
        patterns = pc.detect_patterns("aaabcdef")
        self.assertTrue(any("repeated" in p for p in patterns))

    def test_sequential_ascending(self):
        patterns = pc.detect_patterns("xyzabc123")
        self.assertTrue(any("sequential" in p for p in patterns))

    def test_sequential_descending(self):
        patterns = pc.detect_patterns("321zyx")
        self.assertTrue(any("sequential" in p for p in patterns))

    def test_keyboard_walk(self):
        patterns = pc.detect_patterns("myqwertypass")
        self.assertTrue(any("keyboard" in p for p in patterns))

    def test_clean_password_no_patterns(self):
        patterns = pc.detect_patterns("xK9mQ2vLpR")
        self.assertEqual(patterns, [])


class TestCalculateEntropy(unittest.TestCase):
    def test_empty_password(self):
        self.assertEqual(pc.calculate_entropy(""), 0.0)

    def test_lowercase_only(self):
        # 4 lowercase chars, pool size 26 -> 4 * log2(26)
        expected = 4 * 4.700439718141092
        self.assertAlmostEqual(pc.calculate_entropy("abcd"), expected, places=3)

    def test_full_character_set_scores_higher_than_lowercase_only(self):
        self.assertGreater(pc.calculate_entropy("aB3!aB3!"), pc.calculate_entropy("abcdefgh"))


class TestCheckPasswordStrength(unittest.TestCase):
    def test_common_password_scores_zero(self):
        result = pc.check_password_strength("password")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["label"], "Very Weak")

    def test_leetspeak_common_password_scores_zero(self):
        result = pc.check_password_strength("P@ssw0rd")
        self.assertEqual(result["score"], 0)

    def test_strong_random_password(self):
        result = pc.check_password_strength("xK9$mQ2vL#pR")
        self.assertEqual(result["score"], 5)
        self.assertEqual(result["label"], "Very Strong")

    def test_keyboard_walk_reduces_score(self):
        result = pc.check_password_strength("Qwerty123!ABC")
        self.assertTrue(len(result["patterns"]) > 0)
        self.assertLess(result["score"], 5)

    def test_pwned_count_forces_zero_score(self):
        result = pc.check_password_strength("xK9$mQ2vL#pR", pwned_count=42)
        self.assertEqual(result["score"], 0)
        self.assertIn("42", result["feedback"][0])

    def test_short_password_gets_length_feedback(self):
        result = pc.check_password_strength("xK9$m")
        self.assertTrue(any("8 characters" in f for f in result["feedback"]))


class TestOfflineMode(unittest.TestCase):
    @patch("password_checker.check_pwned")
    def test_no_pwned_check_when_disabled(self, mock_check_pwned):
        # check_password_strength itself never calls check_pwned - it's print_result
        # that decides whether to make the API call, so that's what we test here.
        import io
        import contextlib

        with contextlib.redirect_stdout(io.StringIO()):
            pc.print_result("xK9$mQ2vL#pR", use_pwned=False)

        mock_check_pwned.assert_not_called()


class TestCheckPwned(unittest.TestCase):
    @patch("password_checker.urllib.request.urlopen")
    def test_password_found_in_breach(self, mock_urlopen):
        # Simulate an API response containing our password's hash suffix
        import hashlib
        test_password = "TEST_ONLY_password_123!"
        sha1 = hashlib.sha1(test_password.encode("utf-8")).hexdigest().upper()
        suffix = sha1[5:]

        mock_response = unittest.mock.MagicMock()
        mock_response.read.return_value = f"{suffix}:99\r\nAAAA1111:3\r\n".encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        result = pc.check_pwned(test_password)
        self.assertEqual(result, 99)

    @patch("password_checker.urllib.request.urlopen")
    def test_password_not_found_in_breach(self, mock_urlopen):
        mock_response = unittest.mock.MagicMock()
        mock_response.read.return_value = b"AAAA1111:3\r\nBBBB2222:7\r\n"
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        result = pc.check_pwned("some_password_not_in_the_fake_response")
        self.assertEqual(result, 0)

    @patch("password_checker.urllib.request.urlopen")
    def test_network_failure_returns_none(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("no connection")

        result = pc.check_pwned("anypassword")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
