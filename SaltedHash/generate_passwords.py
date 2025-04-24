import random
import string
import datetime
import os
import nltk
from nltk.corpus import words
import hashlib

# Function to download and save the dictionary file
def download_dictionary():
    print("Downloading dictionary...")
    nltk.download('words')
    word_list = words.words()
    
    # Save the dictionary to a file
    with open('dictionary.txt', 'w') as f:
        for word in word_list:
            if 4 <= len(word) <= 6:
                f.write(word.lower() + '\n')
    
    print(f"Dictionary saved to dictionary.txt")
    return word_list

# Function to generate random string based on character set
def generate_random_string(length, char_set):
    return ''.join(random.choice(char_set) for _ in range(length))

# Function to get a timestamp to use as salt
def get_timestamp():
    return datetime.datetime.now().strftime("%Y%m%d%H%M%S")

# Function to hash a password using MD5
def hash_password(password, salt=""):
    # For unsalted: hash just the password
    # For salted: hash the salt+password
    combined = salt + password
    return hashlib.md5(combined.encode()).hexdigest()

# Function to generate password sets
def generate_password_sets(word_list):
    timestamp = get_timestamp()
    
    # Define character sets
    lower_alpha = string.ascii_lowercase
    full_alpha = string.ascii_letters
    alphanumeric = string.ascii_letters + string.digits
    all_chars = string.ascii_letters + string.digits + string.punctuation
    
    # Create output directory if it doesn't exist
    os.makedirs('password_sets', exist_ok=True)
    
    # Generate the 4 sets of passwords
    sets = [
        ('lower_alpha.txt', lower_alpha),
        ('full_alpha.txt', full_alpha),
        ('alphanumeric.txt', alphanumeric),
        ('all_chars.txt', all_chars)
    ]
    
    for filename, char_set in sets:
        passwords = []
        filepath = os.path.join('password_sets', filename)
        
        # Generate 50 dictionary-based passwords (if applicable)
        dict_words = []
        if char_set == lower_alpha:
            dict_words = [word.lower() for word in word_list if 4 <= len(word) <= 6 and all(c in char_set for c in word)]
        else:
            # For other sets, we'll use a mix of lowercase and manipulated dictionary words
            for word in random.sample([w for w in word_list if 4 <= len(w) <= 6], min(50, len(word_list))):
                modified_word = word
                
                if char_set == full_alpha:
                    # Randomly capitalize some letters
                    modified_word = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in word)
                
                elif char_set == alphanumeric:
                    # Replace some letters with similar numbers
                    replacements = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 'l': '1', 's': '5'}
                    modified_word = ''.join(replacements.get(c.lower(), c) if random.random() > 0.2 else c for c in word)
                
                elif char_set == all_chars:
                    # Add special characters but ensure length stays within 4-6
                    special_chars = '!@#$%^&*()_-+=<>?'
                    word_len = len(word)
                    
                    # Only add special chars if we have room to stay within 6 chars
                    if word_len < 6:
                        # Add special chars at beginning or end, but not both if it would exceed 6 chars
                        if word_len <= 5 and random.random() > 0.5:
                            modified_word = random.choice(special_chars) + word
                            
                        if len(modified_word) < 6 and random.random() > 0.5:
                            modified_word = modified_word + random.choice(special_chars)
                    
                    # If word is already 6 chars, optionally replace a character with special
                    elif word_len == 6:
                        pos = random.randint(0, 5)
                        chars = list(word)
                        chars[pos] = random.choice(special_chars)
                        modified_word = ''.join(chars)
                
                # Ensure the final length is between 4-6
                if 4 <= len(modified_word) <= 6:
                    dict_words.append(modified_word)
                else:
                    # If modification made it too long, truncate or use original
                    dict_words.append(word[:6])
        
        # Use dictionary words for half of the passwords
        num_dict_words = min(50, len(dict_words))
        passwords.extend(random.sample(dict_words, num_dict_words))
        
        # Generate random strings for the rest
        for _ in range(100 - len(passwords)):
            length = random.randint(4, 6)
            passwords.append(generate_random_string(length, char_set))
        
        # Save original passwords, salted passwords, and hashed versions
        with open(filepath, 'w') as f_orig:
            with open(f'password_sets/MD5_{os.path.basename(filepath)}', 'w') as f_md5_unsalted:
                with open(f'password_sets/MD5_salted_{os.path.basename(filepath)}', 'w') as f_md5_salted:
                    # Also save a file mapping hashes to original passwords for verification
                    with open(f'password_sets/hash_map_{os.path.basename(filepath)}', 'w') as f_map:
                        for password in passwords:
                            # Double-check the length constraint before saving
                            if len(password) > 6:
                                password = password[:6]
                            elif len(password) < 4:
                                password = password + generate_random_string(4 - len(password), char_set)
                                
                            # Save original password
                            f_orig.write(f"{password}\n")
                            
                            # Hash without salt (for unsalted tests)
                            md5_hash_unsalted = hash_password(password)
                            f_md5_unsalted.write(f"{md5_hash_unsalted}\n")
                            
                            # Hash with salt (for salted tests)
                            # Using Hashcat's MD5($salt.$pass) format (mode 20)
                            md5_hash_salted = hash_password(password, timestamp)
                            f_md5_salted.write(f"{md5_hash_salted}:{timestamp}\n")
                            
                            # Save mapping for verification
                            f_map.write(f"{password},{md5_hash_unsalted},{md5_hash_salted}\n")
        
        print(f"Generated {len(passwords)} passwords in {filepath}")
        print(f"MD5 hashed versions saved to password_sets/MD5_{os.path.basename(filepath)}")
        print(f"MD5 salted hashed versions saved to password_sets/MD5_salted_{os.path.basename(filepath)}")
    
    # Also save the timestamp as a reference
    with open('password_sets/timestamp.txt', 'w') as f:
        f.write(timestamp)
    
    # Save dictionary in Hashcat format for rule-based attacks
    with open('hashcat_dict.txt', 'w') as f:
        for word in word_list:
            if 4 <= len(word) <= 6:
                f.write(word.lower() + '\n')
    
    return timestamp

def main():
    word_list = download_dictionary()
    timestamp = generate_password_sets(word_list)
    print(f"All password sets generated with salt: {timestamp}")
    print("Files ready for Hashcat testing.")

if __name__ == "__main__":
    main()