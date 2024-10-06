import re

# ANSI color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

def main():
    while True:
        password = input("Enter a password (or 'q' to quit): ")
        if password.lower() == 'q':
            break

        score, feedback = password_strength(password)
        bar, strength = display_strength_bar(score)

        print(f"\nPassword strength: {bar} {strength}")
        if feedback:
            print("Suggestions to improve:")
            for suggestion in feedback:
                print(f"- {suggestion}")
        print()  # Add a newline for better readability

def password_strength(password):
    score = 0
    feedback = []

    # Check length
    if len(password) < 8:
        feedback.append("Password is too short. It should be at least 8 characters.")
    else:
        score += 1

    # Check for uppercase letters
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    # Check for lowercase letters
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    # Check for numbers
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers.")

    # Check for special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add special characters.")

    return score, feedback

def display_strength_bar(score):
    total_bars = 5
    filled_bars = score
    empty_bars = total_bars - filled_bars

    if score <= 2:
        color = RED
        strength = "Weak"
    elif score <= 3:
        color = YELLOW
        strength = "Moderate"
    else:
        color = GREEN
        strength = "Strong"

    bar = f"{color}{'█' * filled_bars}{'░' * empty_bars}{RESET}"
    return bar, strength



if __name__ == "__main__":
    main()