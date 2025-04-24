#!/usr/bin/env python3
import hashlib
import time
import string
import os
import itertools
import matplotlib.pyplot as plt
import numpy as np

def read_password_file(file_path):
    """Read password hashes from a file."""
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file]
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return []

def read_dictionary(file_path):
    """Read dictionary words from a file."""
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file]
    except FileNotFoundError:
        print(f"Error: Dictionary file {file_path} not found.")
        return []

def get_hash(password, salt=""):
    """Generate MD5 hash for a password with optional salt."""
    salted_pass = password + salt
    return hashlib.md5(salted_pass.encode()).hexdigest()

def dictionary_attack(hashes, dictionary, salt=""):
    """Try to crack password hashes using a dictionary."""
    start_time = time.time()
    cracked = {}
    attempts = 0
    
    for word in dictionary:
        attempts += 1
        hash_value = get_hash(word, salt)
        if hash_value in hashes:
            cracked[hash_value] = word
            if len(cracked) == len(hashes):
                break
    
    elapsed_time = time.time() - start_time
    
    return {
        'cracked': cracked,
        'time': elapsed_time,
        'attempts': attempts
    }

def brute_force_attack(hashes, charset, max_length=4, salt=""):
    """Try to crack password hashes using brute force."""
    start_time = time.time()
    cracked = {}
    attempts = 0
    
    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            attempts += 1
            password = ''.join(combo)
            hash_value = get_hash(password, salt)
            
            if hash_value in hashes:
                cracked[hash_value] = password
                if len(cracked) == len(hashes):
                    elapsed_time = time.time() - start_time
                    return {
                        'cracked': cracked,
                        'time': elapsed_time,
                        'attempts': attempts
                    }
    
    elapsed_time = time.time() - start_time
    return {
        'cracked': cracked,
        'time': elapsed_time,
        'attempts': attempts
    }

def create_comparison_plot(unsalted_data, salted_data, metric, charset_name, output_dir="plots"):
    """Create comparison bar plots between salted and unsalted results."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    labels = ['Unsalted', 'Salted']
    values = [unsalted_data, salted_data]
    
    plt.figure(figsize=(10, 6))
    bar_colors = ['#3498db', '#e74c3c']  # Blue for unsalted, Red for salted
    bars = plt.bar(labels, values, color=bar_colors)
    
    # Add a grid for better readability
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Format y-axis for large numbers
    if metric == "Number of Attempts" and max(values) > 1000:
        plt.ticklabel_format(style='plain', axis='y')
    
    plt.ylabel(metric, fontsize=12, fontweight='bold')
    plt.xlabel('Password Type', fontsize=12, fontweight='bold')
    
    title = f'Comparison of {metric} for {charset_name}'
    plt.title(title, fontsize=14, fontweight='bold')
    
    # Add values on top of bars
    for i, bar in enumerate(bars):
        height = bar.get_height()
        if metric == "Time (seconds)":
            display_value = f"{height:.4f}s"
        else:
            display_value = f"{int(height):,}"
        plt.text(bar.get_x() + bar.get_width()/2., height + (max(values) * 0.01),
                 display_value, ha='center', va='bottom', fontweight='bold')
    
    # Save the plot
    filename = f"{charset_name.lower().replace(' ', '_')}_{metric.split()[0].lower()}.png"
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, filename), dpi=300)
    plt.close()
    
    return os.path.join(output_dir, filename)

def get_charset_and_name(charset_type):
    """Get the character set and display name based on type."""
    if charset_type == "full_alpha":
        return string.ascii_lowercase + string.ascii_uppercase, "Full Alphabetic"
    elif charset_type == "lower_alpha":
        return string.ascii_lowercase, "Lowercase Alphabetic"
    elif charset_type == "alphanumeric":
        return string.ascii_lowercase + string.ascii_uppercase + string.digits, "Alphanumeric"
    elif charset_type == "all_chars":
        return string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation, "Full Character Set"
    else:
        return string.ascii_lowercase, "Unknown"

def main():
    # Create plots directory if it doesn't exist
    plots_dir = "plots"
    if not os.path.exists(plots_dir):
        os.makedirs(plots_dir)
    
    # Define charset types for testing
    charset_types = ["full_alpha", "lower_alpha", "alphanumeric", "all_chars"]
    
    # Run tests and generate plots for each charset type
    for charset_type in charset_types:
        print(f"\nProcessing {charset_type}...")
        
        # Get charset and display name
        charset, charset_name = get_charset_and_name(charset_type)
        
        # Prepare file paths
        unsalted_hash_file = f"./password_sets/MD5_{charset_type}.txt"
        salted_hash_file = f"./password_sets/MD5_salted_{charset_type}.txt"
        dict_file = f"./password_sets/{charset_type}.txt"
        
        # Read hash files
        unsalted_hashes = read_password_file(unsalted_hash_file)
        salted_hashes = read_password_file(salted_hash_file)
        
        if not unsalted_hashes or not salted_hashes:
            print(f"Skipping {charset_type} due to missing hash files.")
            continue
        
        print(f"Found {len(unsalted_hashes)} unsalted hashes and {len(salted_hashes)} salted hashes.")
        
        # Try to get salt from file
        salt = ""
        try:
            salt_file = f"./password_sets/{dict_file}.salted"
            with open(salt_file, 'r') as file:
                salt_content = file.readline().strip()
                # Try to extract salt by comparing with original file
                try:
                    with open(dict_file, 'r') as orig_file:
                        orig_content = orig_file.readline().strip()
                        if salt_content.startswith(orig_content):
                            salt = salt_content[len(orig_content):]
                        else:
                            # Default to some common salt if we can't detect it
                            salt = "salt"
                except:
                    salt = "salt"  # Default salt if original file can't be read
        except FileNotFoundError:
            print(f"No salt file found for {charset_type}. Using default salt.")
            salt = "salt"  # Default salt
        
        print(f"Using salt: '{salt}' for salted passwords")
        
        # Read dictionary for dictionary attack
        dictionary = read_dictionary(dict_file)
        if not dictionary:
            print(f"Creating simple dictionary for {charset_type}...")
            # Create a simple dictionary if file not found
            dictionary = [''.join(p) for p in itertools.product(charset[:min(len(charset), 3)], repeat=3)]
        
        # Dictionary attack
        print(f"Running dictionary attack on unsalted {charset_type}...")
        unsalted_dict = dictionary_attack(unsalted_hashes, dictionary)
        
        print(f"Running dictionary attack on salted {charset_type}...")
        salted_dict = dictionary_attack(salted_hashes, dictionary, salt=salt)
        
        # Brute force attack
        print(f"Running brute force attack on unsalted {charset_type}...")
        unsalted_bf = brute_force_attack(unsalted_hashes, charset, max_length=3)
        
        print(f"Running brute force attack on salted {charset_type}...")
        salted_bf = brute_force_attack(salted_hashes, charset, max_length=3, salt=salt)
        
        # Print results
        print(f"\nResults for {charset_name}:")
        print(f"Unsalted brute force: {len(unsalted_bf['cracked'])}/{len(unsalted_hashes)} cracked in {unsalted_bf['time']:.4f}s with {unsalted_bf['attempts']} attempts")
        print(f"Salted brute force: {len(salted_bf['cracked'])}/{len(salted_hashes)} cracked in {salted_bf['time']:.4f}s with {salted_bf['attempts']} attempts")
        print(f"Unsalted dictionary: {len(unsalted_dict['cracked'])}/{len(unsalted_hashes)} cracked in {unsalted_dict['time']:.4f}s with {unsalted_dict['attempts']} attempts")
        print(f"Salted dictionary: {len(salted_dict['cracked'])}/{len(salted_hashes)} cracked in {salted_dict['time']:.4f}s with {salted_dict['attempts']} attempts")
        
        # Create time comparison plot
        time_plot = create_comparison_plot(
            unsalted_bf['time'], 
            salted_bf['time'], 
            "Time (seconds)", 
            charset_name,
            plots_dir
        )
        print(f"Created time comparison plot: {time_plot}")
        
        # Create attempts comparison plot
        attempts_plot = create_comparison_plot(
            unsalted_bf['attempts'], 
            salted_bf['attempts'], 
            "Number of Attempts", 
            charset_name,
            plots_dir
        )
        print(f"Created attempts comparison plot: {attempts_plot}")
    
    print("\nAll processing complete. Plots saved in the 'plots' directory.")

if __name__ == "__main__":
    main()