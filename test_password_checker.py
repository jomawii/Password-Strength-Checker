import contextlib
import hashlib
import io
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

import password_checker as pc


class TestLeetspeak(unittest.TestCase):

    def test_common_leetspeak(self):
        self.assertEqual(
            pc.normalize_leetspeak("P@ssw0rd"),
            "password"
        )

    def test_normal_password_stays_the_same(self):
        self.assertEqual(
            pc.normalize_leetspeak("hello"),
            "hello"
        )


class TestPatterns(unittest.TestCase):

    def test_repeated_characters(self):
        result = pc.detect_patterns("aaabcdef")

        self.assertTrue(
            any("repeated" in pattern for pattern in result)
        )

    def test_sequence_is_detected(self):
        result = pc.detect_patterns("abc123")

        self.assertTrue(
            any("sequential" in pattern for pattern in result)
        )

    def test_keyboard_pattern(self):
        result = pc.detect_patterns("myqwertypass")

        self.assertTrue(
            any("keyboard" in pattern for pattern in result)
        )

    def test_random_looking_password_has_no_patterns(self):
        result = pc.detect_patterns("xK9$mQ2vLpR")

        self.assertEqual(result, [])


class TestEntropy(unittest.TestCase):

    def test_empty_password(self):
        self.assertEqual(
            pc.calculate_entropy(""),
            0.0
        )

    def test_lowercase_entropy(self):
        expected = 4 * __import__("math").log2(26)

        self.assertAlmostEqual(
            pc.calculate_entropy("abcd"),
            expected,
            places=3
        )

    def test_more_character_types_gives_higher_estimate(self):
        mixed = pc.calculate_entropy("aB3!aB3!")
        lowercase = pc.calculate_entropy("abcdefgh")

        self.assertGreater(mixed, lowercase)


class TestPasswordStrength(unittest.TestCase):

    def test_common_password_is_very_weak(self):
        result = pc.check_password_strength("password")

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["label"], "Very Weak")

    def test_leetspeak_version_is_also_rejected(self):
        result = pc.check_password_strength("P@ssw0rd")

        self.assertEqual(result["score"], 0)

    def test_long_mixed_password_is_strong(self):
        result = pc.check_password_strength(
            "xK9$mQ2vL#pR"
        )

        self.assertEqual(result["score"], 5)
        self.assertEqual(result["label"], "Very Strong")

    def test_pattern_lowers_score(self):
        result = pc.check_password_strength(
            "Qwerty123!ABC"
        )

        self.assertTrue(result["patterns"])
        self.assertLess(result["score"], 5)

    def test_breached_password_gets_zero(self):
        result = pc.check_password_strength(
            "xK9$mQ2vL#pR",
            pwned_count=42
        )

        self.assertEqual(result["score"], 0)
        self.assertIn("42", result["feedback"][0])

    def test_short_password_gets_length_warning(self):
        result = pc.check_password_strength("abc")

        self.assertTrue(
            any(
                "8 characters" in message
                for message in result["feedback"]
            )
        )


class TestPwnedCheck(unittest.TestCase):

    @patch("password_checker.urllib.request.urlopen")
    def test_password_found(self, mock_urlopen):
        password = "TEST_ONLY_password_123!"

        password_hash = hashlib.sha1(
            password.encode("utf-8")
        ).hexdigest().upper()

        suffix = password_hash[5:]

        response = MagicMock()
        response.read.return_value = (
            f"{suffix}:99\r\nAAAA1111:3\r\n"
        ).encode("utf-8")

        response.__enter__.return_value = response
        mock_urlopen.return_value = response

        result = pc.check_pwned(password)

        self.assertEqual(result, 99)

    @patch("password_checker.urllib.request.urlopen")
    def test_password_not_found(self, mock_urlopen):
        response = MagicMock()
        response.read.return_value = (
            b"AAAA1111:3\r\nBBBB2222:7\r\n"
        )

        response.__enter__.return_value = response
        mock_urlopen.return_value = response

        result = pc.check_pwned(
            "some_password_not_in_response"
        )

        self.assertEqual(result, 0)

    @patch("password_checker.urllib.request.urlopen")
    def test_api_failure_returns_none(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError(
            "No connection"
        )

        result = pc.check_pwned("anypassword")

        self.assertIsNone(result)


class TestOfflineMode(unittest.TestCase):

    @patch("password_checker.check_pwned")
    def test_offline_mode_does_not_call_api(self, mock_pwned):
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            pc.print_result(
                "xK9$mQ2vL#pR",
                use_pwned=False
            )

        mock_pwned.assert_not_called()


if __name__ == "__main__":
    unittest.main()
