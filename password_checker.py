"""
Password Strength Checker
Author: Jomari Miranda
"""

import re
import math
import os
import sys
import argparse
import hashlib
import urllib.request
import urllib.error
from getpass import getpass

# backup list in case common_passwords.txt isn't found
_FALLBACK_COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "password1", "111111", "letmein", "iloveyou", "admin",
}

LEET_MAP = str.maketrans({
    "@": "a", "4": "a",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t",
})

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]


def load_common_passwords():
    wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common_passwords.txt")
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except OSError:
        return _FALLBACK_COMMON_PASSWORDS


COMMON_PASSWORDS = load_common_passwords()


def normalize_leetspeak(password):
    # turns stuff like P@ssw0rd into password so it still matches the wordlist
    return password.lower().translate(LEET_MAP)


def calculate_entropy(password):
    # theoretical only, assumes random chars which real passwords usually aren't
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
    found = []
    lower = password.lower()

    if re.search(r"(.)\1\1", lower):
        found.append("repeated characters (e.g. 'aaa')")

    for i in range(len(lower) - 2):
        a, b, c = lower[i], lower[i + 1], lower[i + 2]
        if a.isalnum() and b.isalnum() and c.isalnum():
            if ord(b) - ord(a) == 1 and ord(c) - ord(b) == 1:
                found.append("sequential characters (e.g. 'abc', '123')")
                break
            if ord(a) - ord(b) == 1 and ord(b) - ord(c) == 1:
                found.append("sequential characters (e.g. 'cba', '321')")
                break

    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            chunk = row[i:i + 4]
            if chunk in lower or chunk[::-1] in lower:
                found.append(f"keyboard pattern (e.g. '{chunk}')")
                break

    return found


def check_pwned(password, timeout=3.0):
    # k-anonymity check against HIBP - only sends first 5 chars of the sha1 hash,
    # so the real password/hash never leaves the machine
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "password-strength-checker"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None

    for line in body.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return int(parts[1])
    return 0


def check_password_strength(password, pwned_count=None):
    if pwned_count is not None and pwned_count > 0:
        return {
            "score": 0,
            "label": "Very Weak",
            "feedback": [f"This password has appeared in {pwned_count:,} known data breaches."],
            "entropy": round(calculate_entropy(password), 1),
            "patterns": [],
        }

    normalized = normalize_leetspeak(password)
    if password.lower() in COMMON_PASSWORDS or normalized in COMMON_PASSWORDS:
        return {
            "score": 0,
            "label": "Very Weak",
            "feedback": ["This password is widely known and easily guessed (including leetspeak variants)."],
            "entropy": round(calculate_entropy(password), 1),
            "patterns": [],
        }

    feedback = []
    score = 0

    length = len(password)
    if length >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters.")
    if length >= 12:
        score += 1
    else:
        feedback.append("Consider 12+ characters for stronger protection.")

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety = sum([has_lower, has_upper, has_digit, has_special])
    if variety >= 3:
        score += 1
    if variety == 4:
        score += 1

    if not has_upper:
        feedback.append("Add an uppercase letter.")
    if not has_lower:
        feedback.append("Add a lowercase letter.")
    if not has_digit:
        feedback.append("Add a number.")
    if not has_special:
        feedback.append("Add a special character (e.g. ! @ # $ %).")

    score += 1  # not a known common password
    score = min(score, 5)

    patterns = detect_patterns(password)
    if patterns:
        score = max(0, score - 1)
        feedback.append("Avoid predictable patterns: " + "; ".join(patterns) + ".")

    if pwned_count == 0:
        feedback.append("Not found in known breaches (checked via Have I Been Pwned).")

    if score == 5 and not feedback:
        feedback.append("Strong password.")

    labels = {
        0: "Very Weak",
        1: "Weak",
        2: "Fair",
        3: "Good",
        4: "Strong",
        5: "Very Strong",
    }

    return {
        "score": score,
        "label": labels[score],
        "feedback": feedback,
        "entropy": round(calculate_entropy(password), 1),
        "patterns": patterns,
    }


def print_bar(score, max_score=5):
    filled = "#" * score
    empty = "-" * (max_score - score)
    print(f"[{filled}{empty}] {score}/{max_score}")


def print_result(password, use_pwned, label=None):
    pwned_count = check_pwned(password) if use_pwned else None
    result = check_password_strength(password, pwned_count=pwned_count)

    header = f"\n--- {label} ---" if label else ""
    if header:
        print(header)
    print(f"Strength: {result['label']}")
    print_bar(result["score"])
    print(f"Estimated entropy: {result['entropy']} bits")

    if use_pwned and pwned_count is None:
        print("Breach check: could not reach Have I Been Pwned (no internet or API unavailable).")

    if result["feedback"]:
        print("Suggestions:")
        for item in result["feedback"]:
            print(f"  - {item}")

    return result


def run_batch(file_path, use_pwned):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            passwords = [line.rstrip("\n") for line in f if line.strip()]
    except OSError as e:
        print(f"Could not read file: {e}")
        sys.exit(1)

    print(f"Checking {len(passwords)} password(s) from {file_path}...")
    for i, pw in enumerate(passwords, start=1):
        print_result(pw, use_pwned, label=f"Password #{i}")


def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("--file", metavar="PATH", help="check a list of passwords from a text file instead of typing one in")
    parser.add_argument("--no-pwned", action="store_true", help="skip the breach check, run fully offline")
    args = parser.parse_args()

    use_pwned = not args.no_pwned

    print("=" * 50)
    print(" Password Strength Checker")
    print("=" * 50)
    print("Your password is never stored, logged, or written to disk.")
    if use_pwned:
        print("Breach check uses k-anonymity: only a 5-character hash prefix")
        print("is sent over the network. Your full password never leaves this device.")
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
    
