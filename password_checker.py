"""
Password Strength Checker
Author: Jomari Miranda

Checks password length, character variety, common passwords,
predictable patterns, and known data breaches.
"""

import argparse
import hashlib
import math
import os
import re
import sys
import urllib.error
import urllib.request
from getpass import getpass


# Used if common_passwords.txt is missing
FALLBACK_PASSWORDS = {
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "password1",
    "111111",
    "letmein",
    "iloveyou",
    "admin",
}


LEET_MAP = str.maketrans({
    "@": "a",
    "4": "a",
    "3": "e",
    "1": "i",
    "!": "i",
    "0": "o",
    "$": "s",
    "5": "s",
    "7": "t",
})


KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]


def load_common_passwords():
    """Load passwords from common_passwords.txt."""
    file_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "common_passwords.txt"
    )

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return {
                line.strip().lower()
                for line in file
                if line.strip()
            }
    except OSError:
        return FALLBACK_PASSWORDS


COMMON_PASSWORDS = load_common_passwords()


def normalize_leetspeak(password):
    """Convert common leetspeak characters back to letters."""
    return password.lower().translate(LEET_MAP)


def calculate_entropy(password):
    """
    Estimate theoretical entropy.

    This assumes characters were chosen randomly, so it should
    not be treated as a perfect measurement of real password strength.
    """
    pool_size = 0

    if re.search(r"[a-z]", password):
        pool_size += 26

    if re.search(r"[A-Z]", password):
        pool_size += 26

    if re.search(r"[0-9]", password):
        pool_size += 10

    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 32

    if pool_size == 0:
        return 0.0

    return len(password) * math.log2(pool_size)


def detect_patterns(password):
    """Find simple patterns that make passwords easier to guess."""
    patterns = []
    password = password.lower()

    # Repeated characters such as aaa or 111
    if re.search(r"(.)\1\1", password):
        patterns.append("repeated characters (e.g. 'aaa')")

    # Simple ascending or descending sequences
    for i in range(len(password) - 2):
        a = password[i]
        b = password[i + 1]
        c = password[i + 2]

        if not (a.isalnum() and b.isalnum() and c.isalnum()):
            continue

        if ord(b) - ord(a) == 1 and ord(c) - ord(b) == 1:
            patterns.append("sequential characters (e.g. 'abc', '123')")
            break

        if ord(a) - ord(b) == 1 and ord(b) - ord(c) == 1:
            patterns.append("sequential characters (e.g. 'cba', '321')")
            break

    # Common keyboard walks such as qwerty or 1234
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            sequence = row[i:i + 4]

            if sequence in password or sequence[::-1] in password:
                patterns.append(f"keyboard pattern (e.g. '{sequence}')")
                break

    return patterns


def check_pwned(password, timeout=3.0):
    """
    Check the password against Have I Been Pwned.

    Only the first five characters of the SHA-1 hash are sent.
    The complete password and complete hash stay on the device.

    Returns:
        Number of breaches if found
        0 if not found
        None if the API cannot be reached
    """
    password_hash = hashlib.sha1(
        password.encode("utf-8")
    ).hexdigest().upper()

    prefix = password_hash[:5]
    suffix = password_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "password-strength-checker"
            }
        )

        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read().decode("utf-8")

    except (urllib.error.URLError, TimeoutError, OSError):
        return None

    for line in data.splitlines():
        parts = line.split(":")

        if len(parts) == 2 and parts[0] == suffix:
            return int(parts[1])

    return 0


def check_password_strength(password, pwned_count=None):
    """Calculate a password's strength and return feedback."""
    # A password found in a breach is never safe
    if pwned_count is not None and pwned_count > 0:
        return {
            "score": 0,
            "label": "Very Weak",
            "feedback": [
                f"This password has appeared in "
                f"{pwned_count:,} known data breaches."
            ],
            "entropy": round(calculate_entropy(password), 1),
            "patterns": [],
        }

    normalized = normalize_leetspeak(password)

    if (
        password.lower() in COMMON_PASSWORDS
        or normalized in COMMON_PASSWORDS
    ):
        return {
            "score": 0,
            "label": "Very Weak",
            "feedback": [
                "This password is commonly used or easily guessed."
            ],
            "entropy": round(calculate_entropy(password), 1),
            "patterns": [],
        }

    score = 0
    feedback = []

    length = len(password)

    # Length is more important than simply adding symbol
    if length >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters.")

    if length >= 12:
        score += 1
    else:
        feedback.append("Consider using 12 or more characters.")

    if length >= 16:
        score += 1

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety = 0

    if has_lower:
        variety += 1
    if has_upper:
        variety += 1
    if has_digit:
        variety += 1
    if has_special:
        variety += 1

    # Character variety is useful, but it doesn't make the pass safe
    if variety >= 3:
        score += 1

    if not has_upper:
        feedback.append("Add an uppercase letter if appropriate.")
    if not has_lower:
        feedback.append("Add a lowercase letter if appropriate.")
    if not has_digit:
        feedback.append("Adding a number can increase variety.")
    if not has_special:
        feedback.append("Adding a special character can increase variety.")

    # Being unique enough to not appear in anything (+1)
    score += 1

    patterns = detect_patterns(password)

    if patterns:
        score -= 1
        feedback.append(
            "Avoid predictable patterns: "
            + "; ".join(patterns)
            + "."
        )

    score = max(0, min(score, 5))

    if pwned_count == 0:
        feedback.append(
            "Not found in known breaches "
            "(checked through Have I Been Pwned)."
        )

    labels = {
        0: "Very Weak",
        1: "Weak",
        2: "Fair",
        3: "Good",
        4: "Strong",
        5: "Very Strong",
    }

    if score == 5 and not feedback:
        feedback.append("Strong password.")

    return {
        "score": score,
        "label": labels[score],
        "feedback": feedback,
        "entropy": round(calculate_entropy(password), 1),
        "patterns": patterns,
    }


def print_bar(score):
    """Print a simple strength meter."""
    filled = "#" * score
    empty = "-" * (5 - score)

    print(f"[{filled}{empty}] {score}/5")


def print_result(password, use_pwned=True, label=None):
    """Check and display one password."""
    pwned_count = None

    if use_pwned:
        pwned_count = check_pwned(password)

    result = check_password_strength(
        password,
        pwned_count=pwned_count
    )

    if label:
        print(f"\n--- {label} ---")

    print(f"Strength: {result['label']}")
    print_bar(result["score"])
    print(f"Estimated entropy: {result['entropy']} bits")

    if use_pwned and pwned_count is None:
        print(
            "Breach check: unavailable "
            "(no internet connection or API error)."
        )

    if result["feedback"]:
        print("Suggestions:")

        for message in result["feedback"]:
            print(f"  - {message}")

    return result


def run_batch(file_path, use_pwned):
    """Check passwords stored one per line in a text file."""
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            passwords = [
                line.rstrip("\n")
                for line in file
                if line.strip()
            ]

    except OSError as error:
        print(f"Could not read file: {error}")
        sys.exit(1)

    print(
        f"Checking {len(passwords)} password(s) "
        f"from {file_path}..."
    )

    for number, password in enumerate(passwords, start=1):
        print_result(
            password,
            use_pwned,
            label=f"Password #{number}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Password Strength Checker"
    )

    parser.add_argument(
        "--file",
        metavar="PATH",
        help="check passwords from a text file"
    )

    parser.add_argument(
        "--no-pwned",
        action="store_true",
        help="skip the breach check"
    )

    args = parser.parse_args()

    use_pwned = not args.no_pwned

    print("=" * 50)
    print(" Password Strength Checker")
    print("=" * 50)

    print(
        "Your password is not stored or written to disk."
    )

    if use_pwned:
        print(
            "HIBP uses k-anonymity. Only the first 5 characters "
            "of the password hash are sent."
        )

    print()

    if args.file:
        run_batch(args.file, use_pwned)
        return

    try:
        password = getpass("Enter a password to check: ")

    except (EOFError, KeyboardInterrupt):
        print("\nNo input received. Exiting.")
        return

    if not password:
        print("No password entered.")
        return

    print_result(password, use_pwned)


if __name__ == "__main__":
    main()
