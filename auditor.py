import math
import re

#Part 1

def load_common_passwords(file_path="common_passwords.txt"):
    passwords = set()
    try:
        file = open(file_path, "r")
        for line in file:
            passwords.add(line.strip().lower())
        file.close()
    except FileNotFoundError:
        pass
    return passwords

COMMON_PASSWORDS = load_common_passwords()

#Part 2 : Entropy checking

def calculate_entropy(password):
    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        charset += 32

    if charset == 0:
        return 0

    return len(password) * math.log2(charset)

#Part 3: Dictionary checking

def dictionary_check(password):
    pwd = password.lower()
    if pwd in COMMON_PASSWORDS:
        return True

    for word in COMMON_PASSWORDS:
        if word in pwd:
            return True

    return False

#Part 4: Pattern

def pattern_detection(password):
    patterns = [
        r"(.)\1{2,}",             
        r"1234|abcd|qwerty",      
        r"\d{4}",                
    ]

    for pattern in patterns:
        if re.search(pattern, password.lower()):
            return True
    return False

#Part 5

def audit_password(password):
    score = 0
    result = []

    entropy = calculate_entropy(password)

    if entropy < 40:
        result.append("Low entropy: password is predictable")
    else:
        score += min(entropy, 60)

    if dictionary_check(password):
        result.append("Contains dictionary or common password")
        score -= 20

    if pattern_detection(password):
        result.append("Contains common patterns or repetitions")
        score -= 15

    if len(password) >= 12:
        score += 10
    else:
        result.append("Password length should be at least 12 characters")

    score = max(0, min(100, score))

    if score < 40:
        strength = "Very Weak"
    elif score < 60:
        strength = "Weak"
    elif score < 80:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return {
        "Password": password,
        "Entropy": round(entropy, 2),
        "Score": score,
        "Strength": strength,
        "Result": result
    }

#Part 6

if __name__ == "__main__":
    pwd = input("Enter password to audit: ")
    result = audit_password(pwd)

    print("\n Password Audit Report")
    for key, value in result.items():
        print(f"{key}: {value}")
