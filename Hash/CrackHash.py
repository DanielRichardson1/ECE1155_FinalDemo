import string
import time
import itertools
import hashlib
import bcrypt
import argon2
import random


def create_password_dictionary():
    """
    Creates a dictionary of 1000 passwords with our target words at random positions.
    
    Returns:
    list: List of 1000 passwords
    """
    dictionary_words = [
        "123",
        "1234",
        "12345",
        "123456",
        "abc",
        "pass",
        "xxxxx",
        "secret",
        "hi1",
        "abc1",
        "pass1",
        "xxxxx1",
        "AbC",
        "Pass",
        "xXxXx",
        "Secret"
    ]
    
    large_dictionary = [""] * 1000
    used_positions = set()
    
    for word in dictionary_words:
        while True:
            position = random.randint(0, 999)
            if position not in used_positions:
                large_dictionary[position] = word
                used_positions.add(position)
                break
    
    # Fill remaining positions with random strings (not actual targets)
    for i in range(1000):
        if i not in used_positions:
            filler_length = random.randint(3, 8)
            filler_chars = [random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(filler_length)]
            large_dictionary[i] = ''.join(filler_chars)
    
    return large_dictionary

# Create dictionary once
PASSWORD_DICTIONARY = create_password_dictionary()


def crack_password_bf(hashed_password, algorithm="sha256", known_charset="numeric"):
    """
    Brute Force Password Cracking Function, assumes a known charset to mock real-world and speed up simulation
    
    Parameters:
    hashed_password (str): The hashed password to crack
    algorithm (str): The hashing algorithm used - "md5", "sha256", "bcrypt", or "argon2"
    known_charset (str): The charset category to try - "numeric", "lowercase", 
                        "lowercase_numeric", or "full_alphabetic"
    
    Returns:
    tuple: (success_boolean, time_taken_seconds, cracked_password)
            If unsuccessful, returns (False, time_taken_seconds or 200, None)
    """
    # Define character sets based on category
    charset_map = {
        "numeric": string.digits,
        "lowercase": string.ascii_lowercase,
        "lowercase_numeric": string.ascii_lowercase + string.digits,
        "full_alphabetic": string.ascii_letters
    }
    
    charset = charset_map.get(known_charset, string.ascii_letters + string.digits)
    
    start_time = time.time()
    time_limit = 200  # 200 seconds time limit
    
    # Set up hasher function based on algorithm
    def check_hash(password_attempt):
        if algorithm.lower() == "md5":
            return hashlib.md5(password_attempt.encode()).hexdigest() == hashed_password
        
        elif algorithm.lower() == "sha256":
            return hashlib.sha256(password_attempt.encode()).hexdigest() == hashed_password
        
        elif algorithm.lower() == "bcrypt":
            try:
                return bcrypt.checkpw(password_attempt.encode(), hashed_password.encode())
            except ValueError:
                # If the hash format is invalid
                return False
        
        elif algorithm.lower() == "argon2":
            ph = argon2.PasswordHasher(
                time_cost=1,     # Reduced from default 2
                memory_cost=8,   # Reduced from default 65536
                parallelism=1    # Reduced from default 4
            )
            try:
                ph.verify(hashed_password, password_attempt)
                return True
            except (argon2.exceptions.VerifyMismatchError, ValueError):
                return False
        
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    # Try passwords of length 3 to 6
    for length in range(3, 7):
        print(f"Trying length {length} with charset: {known_charset}")
        
        # Generate all possible combinations for current length and charset
        for attempt in itertools.product(charset, repeat=length):
            # Check if time limit exceeded
            if time.time() - start_time > time_limit:
                duration = time.time() - start_time
                return False, min(duration, 200), None
            
            password_attempt = ''.join(attempt)
            
            # Check if we found a match
            if check_hash(password_attempt):
                duration = time.time() - start_time
                return True, duration, password_attempt
    
    # We've tried everything and found nothing 
    duration = time.time() - start_time
    return False, min(duration, 200), None

def crack_password_dict(hashed_password, algorithm="sha256"):
    """
    Dictionary Attack Function, uses fake dictionary of size 1,000 that includes half of the passwords
    
    Parameters:
    hashed_password (str): The hashed password to crack
    algorithm (str): The hashing algorithm used - "md5", "sha256", "bcrypt", or "argon2"
    
    Returns:
    tuple: (success_boolean, time_taken_seconds, cracked_password)
            If unsuccessful, returns (False, time_taken_seconds or 200, None)
    """
    # Set up hasher function based on algorithm
    def check_hash(password_attempt):
        if algorithm.lower() == "md5":
            return hashlib.md5(password_attempt.encode()).hexdigest() == hashed_password
        
        elif algorithm.lower() == "sha256":
            return hashlib.sha256(password_attempt.encode()).hexdigest() == hashed_password
        
        elif algorithm.lower() == "bcrypt":
            try:
                return bcrypt.checkpw(password_attempt.encode(), hashed_password.encode())
            except ValueError:
                # If the hash format is invalid
                return False
        
        elif algorithm.lower() == "argon2":
            ph = argon2.PasswordHasher()
            try:
                ph.verify(hashed_password, password_attempt)
                return True
            except (argon2.exceptions.VerifyMismatchError, ValueError):
                return False
        
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    start_time = time.time()
    time_limit = 200  # 200 seconds time limit
    
    # Try each word in the dictionary
    for i, password_attempt in enumerate(PASSWORD_DICTIONARY):
        # Check if time limit exceeded
        if time.time() - start_time > time_limit:
            duration = time.time() - start_time
            return False, min(duration, 200), None
        
        # Progress indicator (optional)
        if i % 100 == 0:
            print(f"Tried {i} passwords...")
        
        # Check if we found a match
        if check_hash(password_attempt):
            duration = time.time() - start_time
            return True, duration, password_attempt
    
    # If we've tried everything and found nothing
    duration = time.time() - start_time
    return False, min(duration, 200), None