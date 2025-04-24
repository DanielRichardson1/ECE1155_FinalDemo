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
            if len(word) == 5:  # Only length 5
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
    # For salted: hash the salt+password (salt added BEFORE hashing)
    combined = salt + password
    return hashlib.md5(combined.encode()).hexdigest()

# Function to generate modified dictionary words based on character set
def generate_modified_words(word_list, char_set, num_words=4):
    # Filter words of length 5
    filtered_words = [w for w in word_list if len(w) == 5]
    
    if not filtered_words:
        return []
    
    passwords = []
    sample_words = random.sample(filtered_words, min(num_words, len(filtered_words)))
    
    for word in sample_words:
        modified_word = word
        
        if char_set == string.ascii_lowercase:
            # Just use lowercase word
            modified_word = word.lower()
        
        elif char_set == string.ascii_letters:
            # Randomly capitalize some letters
            modified_word = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in word)
        
        elif char_set == string.ascii_letters + string.digits:
            # Replace some letters with similar numbers
            replacements = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 'l': '1', 's': '5'}
            modified_word = ''.join(replacements.get(c.lower(), c) if random.random() > 0.2 else c for c in word)
        
        elif string.punctuation in char_set:
            # Replace a character with a special character
            special_chars = '!@#$%^&*()_-+=<>?'
            pos = random.randint(0, 4)
            chars = list(word.lower())
            chars[pos] = random.choice(special_chars)
            modified_word = ''.join(chars)
        
        # Only add if it's exactly length 5
        if len(modified_word) == 5:
            passwords.append(modified_word)
    
    return passwords

# Function to generate two separate sets of passwords
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
        # Generate TWO SEPARATE password sets - one for unsalted, one for salted
        unsalted_passwords = []
        salted_passwords = []
        filepath = os.path.join('password_sets', filename)
        
        # Generate dictionary-based passwords for unsalted
        unsalted_passwords.extend(generate_modified_words(word_list, char_set))
        
        # Generate dictionary-based passwords for salted (different from unsalted)
        salted_passwords.extend(generate_modified_words(word_list, char_set))
        
        # Generate random strings to complete sets (6 passwords each)
        while len(unsalted_passwords) < 6:
            unsalted_passwords.append(generate_random_string(5, char_set))
        
        while len(salted_passwords) < 6:
            # Make sure we don't use the same passwords as unsalted
            new_pwd = generate_random_string(5, char_set)
            if new_pwd not in unsalted_passwords:
                salted_passwords.append(new_pwd)
        
        # Save original passwords, salted passwords, and hashed versions
        with open(filepath, 'w') as f_orig:
            # New file for salted plaintext
            with open(f'{filepath}.salted', 'w') as f_salted_plain:
                with open(f'password_sets/MD5_{os.path.basename(filepath)}', 'w') as f_md5_unsalted:
                    with open(f'password_sets/MD5_salted_{os.path.basename(filepath)}', 'w') as f_md5_salted:
                        # Also save a file mapping hashes to original passwords for verification
                        with open(f'password_sets/hash_map_{os.path.basename(filepath)}', 'w') as f_map:
                            # Process unsalted passwords
                            for password in unsalted_passwords:
                                # Save original password
                                f_orig.write(f"{password}\n")
                                
                                # Hash without salt (for unsalted tests)
                                md5_hash_unsalted = hash_password(password)
                                f_md5_unsalted.write(f"{md5_hash_unsalted}\n")
                                
                                # Save mapping for verification
                                f_map.write(f"{password},{md5_hash_unsalted},unsalted\n")
                            
                            # Process salted passwords (completely different set)
                            for password in salted_passwords:
                                # Save salted plaintext (salt+password)
                                salted_plaintext = timestamp + password
                                f_salted_plain.write(f"{salted_plaintext}\n")
                                
                                # Hash with salt (for salted tests)
                                # Using Hashcat's MD5($salt.$pass) format (mode 20)
                                md5_hash_salted = hash_password(password, timestamp)
                                f_md5_salted.write(f"{md5_hash_salted}:{timestamp}\n")
                                
                                # Save mapping for verification
                                f_map.write(f"{password},salted,{md5_hash_salted}\n")
        
        print(f"Generated {len(unsalted_passwords)} unsalted passwords in {filepath}")
        print(f"Generated {len(salted_passwords)} salted passwords in {filepath}.salted")
        print(f"MD5 hashed versions saved to password_sets/MD5_{os.path.basename(filepath)}")
        print(f"MD5 salted hashed versions saved to password_sets/MD5_salted_{os.path.basename(filepath)}")
    
    # Also save the timestamp as a reference
    with open('password_sets/timestamp.txt', 'w') as f:
        f.write(timestamp)
    
    # Save dictionary in Hashcat format for rule-based attacks
    with open('hashcat_dict.txt', 'w') as f:
        for word in word_list:
            if len(word) == 5:
                f.write(word.lower() + '\n')
    
    return timestamp

def main():
    word_list = download_dictionary()
    timestamp = generate_password_sets(word_list)
    print(f"All password sets generated with salt: {timestamp}")
    print("Files ready for Hashcat testing.")

if __name__ == "__main__":
    main()