"""
Password Strength Checker

Evaluates password strength based on length, character variety, and
common weak-password patterns. Runs entirely LOCALLY.

Author: Jomari Miranda
"""

import re
import math
import os
from getpass import getpass

# Small built-in fallback just in case common_passwords.txt is missing or unreadable.
_FALLBACK_COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "password1", "111111", "letmein", "iloveyou", "admin",
}


def load_common_passwords() -> set:
    """Load the common-password wordlist from common_passwords.txt.
    Falls back to a small built-in list if the file is missing """
    wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common_passwords.txt")
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except OSError:
        return _FALLBACK_COMMON_PASSWORDS


COMMON_PASSWORDS = load_common_passwords()


def calculate_entropy(password: str) -> float:
    """Estimate password entropy in bits based on detected character pool size.
    This is a THEORETICAL estimate that assumes random character selection. """
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


def check_password_strength(password: str) -> dict:
    """
    Score a password from 0-5.
    """
    if password.lower() in COMMON_PASSWORDS:
        return {
            "score": 0,
            "label": "Very Weak",
            "feedback": ["This password is widely known and easily guessed."],
            "entropy": round(calculate_entropy(password), 1),
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
    }


def print_bar(score: int, max_score: int = 5) -> None:
    """Print a visual strength bar in the terminal."""
    filled = "#" * score
    empty = "-" * (max_score - score)
    print(f"[{filled}{empty}] {score}/{max_score}")


def main():
    print("=" * 50)
    print(" Password Strength Checker")
    print("=" * 50)
    print("Your password is not stored or transmitted anywhere.\n")

    try:
        password = getpass("Enter a password to check: ")
    except (EOFError, KeyboardInterrupt):
        print("\nNo input received. Exiting.")
        return

    if not password:
        print("No password entered.")
        return

    result = check_password_strength(password)

    print(f"\nStrength: {result['label']}")
    print_bar(result["score"])
    print(f"Estimated entropy: {result['entropy']} bits")

    if result["feedback"]:
        print("\nSuggestions:")
        for item in result["feedback"]:
            print(f"  - {item}")


if __name__ == "__main__":
    main()
