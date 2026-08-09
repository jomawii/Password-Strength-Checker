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

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback = ["ts is weak and is common"]
    elif score == 5 and not feedback:
        feedback.append("Strong password wowee")
    else:
        score += 1  

    score = max(0, min(score, 5))

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
