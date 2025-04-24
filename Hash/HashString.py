import hashlib
import time
import bcrypt
import argon2


def hash_string(input_string, algorithm="sha256"):
    """
    Hash a string using the specified algorithm and return the hash & execution time.
    
    Parameters:
    input_string (str): The string to hash
    algorithm (str): The hashing algorithm to use - "md5", "sha256", "bcrypt", or "argon2"
    
    Returns:
    tuple: (hash_result, execution_time_ms)
    """
    start_time = time.time()
    result = None
    
    if algorithm.lower() == "md5":
        result = hashlib.md5(input_string.encode()).hexdigest()
    
    elif algorithm.lower() == "sha256":
        result = hashlib.sha256(input_string.encode()).hexdigest()
    
    elif algorithm.lower() == "bcrypt":
        # bcrypt requires a salt and works with bytes
        salt = bcrypt.gensalt(rounds=4)
        result = bcrypt.hashpw(input_string.encode(), salt).decode('utf-8')
    
    elif algorithm.lower() == "argon2":
        # Using argon2 with minimal parameters for simulation speed
        ph = argon2.PasswordHasher(
            time_cost=1,      # Default is 2
            memory_cost=8,    # Default is much higher (65536 KiB)
            parallelism=1     # Default is 4
        )
        result = ph.hash(input_string)
    
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Choose from 'md5', 'sha256', 'bcrypt', or 'argon2'.")
    
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000  # Convert to milliseconds
    
    return result, execution_time_ms
