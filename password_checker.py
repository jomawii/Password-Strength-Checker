"""
Author: Jomawii
"""

import re
import math

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "password1", "111111", "letmein", "iloveyou", "admin",
    "welcome", "monkey", "dragon", "football", "123123",
}


def calculate_entropy(password: str) -> float:
    """
    Rough theoretical entropy estimate, NOT a real crack-time measurement teehee.

    This assumes characters were chosen randomly from the detected
    character pool. Real human passwords aint random smth like
    "Jomari123!" can score a decent theoretical entropy here while still
    being predictable (name + common number pattern + common symbol)
    Treat this number as a loose signal, not a guarantee of strength.
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


def check_password_strength(password: str) -> dict:
    """
    Score breakdown (max 5 points total):
      - length >= 8:  +1
      - length >= 12: +1
      - variety >= 3 character types: +1
      - variety == 4 character types: +1
      - not a known common password: +1 (only point, not stacked per-feedback-item)
    """
    feedback = []
    score = 0

    # Common password check 1st
    if password.lower() in COMMON_PASSWORDS:
        return {
            "score": 0,
            "label": "Very Weak",
            "feedback": ["ts is weak and is common"],
            "entropy": round(calculate_entropy(password), 1),
        }

    # Length
    length = len(password)
    if length >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters.")
    if length >= 12:
        score += 1
    else:
        feedback.append("Consider 12+ characters for stronger protection.")

    # check variety type shi
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

    # bonus point for not being a common password
    score += 1

    score = max(0, min(score, 5))

    if score == 5 and not feedback:
        feedback.append("Strong password wowee")

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
    """Print a simple visual strength bar in the terminal."""
    filled = "#" * score
    empty = "-" * (max_score - score)
    print(f"[{filled}{empty}] {score}/{max_score}")


def main():
    print("=" * 50)
    print(" Password Strength Checker")
    print("=" * 50)
    print("Your password is not stored or transmitted anywhere.\n")

    try:
        password = input("Enter a password to check: ")
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
    
