import hashlib
import time
import string
from itertools import product

def check_password_strength(password):
    """
    Password Strength Checker
    -------------------------
    1. Checks password length and complexity
    2. Evaluates strength based on character types
    3. Estimates brute-force attack time
    """
    score = 0
    
    if len(password) >= 8:
        score += 1
    if any(char.isdigit() for char in password):
        score += 1
    if any(char.islower() for char in password):
        score += 1
    if any(char.isupper() for char in password):
        score += 1
    if any(char in string.punctuation for char in password):
        score += 1
    
    strength_levels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
    return strength_levels[score]

def brute_force_time(password):
    charset = string.ascii_letters + string.digits + string.punctuation
    start_time = time.time()
    
    for length in range(1, len(password) + 1):
        for attempt in product(charset, repeat=length):
            attempt = ''.join(attempt)
            if attempt == password:
                return time.time() - start_time
    return "Too long to calculate"

if __name__ == "__main__":
    print("""
    Password Strength Tester
    ------------------------
    This tool checks your password strength and estimates the brute-force cracking time.
    
    Usage:
    ------
    1. Run the script
    2. Enter a password to analyze
    3. Get strength rating and estimated attack time
    """)
    
    user_password = input("Enter a password to check strength: ")
    strength = check_password_strength(user_password)
    print(f"Password Strength: {strength}")
    
    estimated_time = brute_force_time(user_password)
    print(f"Estimated brute-force time: {estimated_time} seconds")
