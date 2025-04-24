import os
import subprocess
import datetime
import time
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import re

# Configuration
OUTPUT_DIR = "results"
PLOTS_DIR = "plots"

# Hashcat hash modes
UNSALTED_HASH_MODE = "0"  # MD5
SALTED_HASH_MODE = "20"   # MD5($salt.$pass)

# Create output directories
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(PLOTS_DIR, exist_ok=True)

# Get the timestamp from the file
with open('password_sets/timestamp.txt', 'r') as f:
    TIMESTAMP = f.read().strip()

# Function to run Hashcat and collect data
def run_cracking_test(password_file, use_salt=True, attack_mode="dictionary"):
    base_filename = os.path.basename(password_file).replace('MD5_', '').replace('salted_', '').replace('.txt', '')
    salt_suffix = "salted" if use_salt else "unsalted"
    attack_suffix = attack_mode
    
    result_file = f"{OUTPUT_DIR}/{base_filename}_{salt_suffix}_{attack_suffix}_results.txt"
    stats_file = f"{OUTPUT_DIR}/{base_filename}_{salt_suffix}_{attack_suffix}_stats.csv"
    
    print(f"Running {attack_mode} attack on {base_filename} ({salt_suffix})...")
    
    # Prepare the input file based on whether we're using salt or not
    input_file = f"password_sets/MD5_salted_{base_filename}.txt" if use_salt else f"password_sets/MD5_{base_filename}.txt"
    hash_mode = SALTED_HASH_MODE if use_salt else UNSALTED_HASH_MODE
    
    # Start time
    start_time = time.time()
    
    # Data collection setup
    times = []
    cracked_counts = []
    attempts = []
    current_attempt = 0
    
    if attack_mode == "dictionary":
        # Dictionary attack
        cmd = [
            "hashcat", 
            "-m", hash_mode, 
            "-a", "0",  # Dictionary attack
            "--force",
            "-o", result_file,
            input_file,
            "dictionary.txt"
        ]
        
        # Add status monitor
        cmd += ["--status", "--status-timer=1"]
        
        # Run the command
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Parse output in real-time to collect stats
        for line in iter(process.stdout.readline, ''):
            print(line, end='')
            
            # Extract progress info from status lines
            if "Speed" in line:
                elapsed = time.time() - start_time
                
                # Try to extract progress
                match = re.search(r'Recovered\.+: (\d+)/(\d+)', line)
                if match:
                    cracked = int(match.group(1))
                    total = int(match.group(2))
                    
                    # Record data point
                    times.append(elapsed)
                    cracked_counts.append(cracked)
                    
                    # Estimate attempts from speed info
                    speed_match = re.search(r'Speed\.#1\.+: (\d+[\.\d]*) (.H/s)', line)
                    if speed_match:
                        speed = float(speed_match.group(1))
                        unit = speed_match.group(2)
                        
                        # Convert to H/s based on unit
                        if 'kH/s' in unit:
                            speed *= 1000
                        elif 'MH/s' in unit:
                            speed *= 1000000
                        elif 'GH/s' in unit:
                            speed *= 1000000000
                        
                        current_attempt += speed
                        attempts.append(current_attempt)
        
        process.wait()
        
    else:  # Brute force attack
        total_cracked = 0
        total_passwords = sum(1 for _ in open(input_file))
        
        # Run brute force for lengths 4-6
        for length in range(4, 7):
            print(f"Trying length {length}...")
            
            # Set mask based on password type
            if 'lower_alpha' in base_filename:
                mask = ''.join(['?l'] * length)
            elif 'full_alpha' in base_filename:
                mask = ''.join(['?a'] * length)  # ?a includes uppercase and lowercase
            elif 'alphanumeric' in base_filename:
                mask = ''.join(['?a'] * length)  # ?a includes alphanumeric
            else:  # all_chars
                mask = ''.join(['?a'] * length)  # ?a includes all ASCII
            
            # Run hashcat with brute force
            cmd = [
                "hashcat", 
                "-m", hash_mode, 
                "-a", "3",  # Brute force attack
                "--force",
                "-o", result_file,
                input_file,
                mask
            ]
            
            # Add status monitor
            cmd += ["--status", "--status-timer=1"]
            
            # Run the command
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Parse output in real-time to collect stats
            for line in iter(process.stdout.readline, ''):
                print(line, end='')
                
                # Extract progress info from status lines
                if "Speed" in line:
                    elapsed = time.time() - start_time
                    
                    # Try to extract progress
                    match = re.search(r'Recovered\.+: (\d+)/(\d+)', line)
                    if match:
                        cracked = int(match.group(1))
                        total = int(match.group(2))
                        
                        # Record data point
                        times.append(elapsed)
                        cracked_counts.append(total_cracked + cracked)
                        
                        # Estimate attempts from speed info
                        speed_match = re.search(r'Speed\.#1\.+: (\d+[\.\d]*) (.H/s)', line)
                        if speed_match:
                            speed = float(speed_match.group(1))
                            unit = speed_match.group(2)
                            
                            # Convert to H/s based on unit
                            if 'kH/s' in unit:
                                speed *= 1000
                            elif 'MH/s' in unit:
                                speed *= 1000000
                            elif 'GH/s' in unit:
                                speed *= 1000000000
                            
                            current_attempt += speed
                            attempts.append(current_attempt)
            
            process.wait()
            
            # Count cracked passwords after this length iteration
            if os.path.exists(result_file):
                cracked_this_round = sum(1 for _ in open(result_file)) - total_cracked
                total_cracked += cracked_this_round
            
            # If all passwords are cracked, stop
            if total_cracked >= total_passwords:
                break
    
    # End time
    end_time = time.time()
    elapsed = end_time - start_time
    
    # Count final cracked passwords
    cracked = 0
    if os.path.exists(result_file):
        cracked = sum(1 for _ in open(result_file))
    
    total = sum(1 for _ in open(input_file))
    
    print(f"Test completed in {elapsed:.2f} seconds")
    print(f"Cracked {cracked} out of {total} passwords")
    
    # Save raw data for plotting
    df = pd.DataFrame({
        'Time': times,
        'Cracked': cracked_counts,
        'Attempts': attempts
    })
    df.to_csv(stats_file, index=False)
    
    return {
        'file': base_filename,
        'salt': use_salt,
        'attack': attack_mode,
        'time': elapsed,
        'cracked': cracked,
        'total': total,
        'success_rate': cracked / total if total > 0 else 0,
        'stats_file': stats_file
    }

# Function to create plots
def create_plots(results):
    # Group results by password file and attack type
    grouped_results = {}
    for result in results:
        key = (result['file'], result['attack'])
        if key not in grouped_results:
            grouped_results[key] = []
        grouped_results[key].append(result)
    
    # Create plots for each password set and attack type
    for (file, attack), result_group in grouped_results.items():
        # Sort results by salted/unsalted
        result_group.sort(key=lambda x: x['salt'])
        
        # Time comparison plot
        plt.figure(figsize=(10, 6))
        plt.bar(
            ['Unsalted', 'Salted'], 
            [r['time'] for r in result_group],
            color=['skyblue', 'navy']
        )
        plt.title(f'Time to Crack: {file} ({attack} attack)')
        plt.ylabel('Time (seconds)')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.savefig(f'{PLOTS_DIR}/{file}_{attack}_time_comparison.png')
        plt.close()
        
        # Success rate comparison plot
        plt.figure(figsize=(10, 6))
        plt.bar(
            ['Unsalted', 'Salted'], 
            [r['success_rate'] * 100 for r in result_group],
            color=['lightgreen', 'darkgreen']
        )
        plt.title(f'Success Rate: {file} ({attack} attack)')
        plt.ylabel('Success Rate (%)')
        plt.ylim(0, 100)
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.savefig(f'{PLOTS_DIR}/{file}_{attack}_success_comparison.png')
        plt.close()
        
        # Time vs. Cracked progress plot (if we have detailed stats files)
        for result in result_group:
            if os.path.exists(result['stats_file']):
                try:
                    df = pd.read_csv(result['stats_file'])
                    if len(df) > 1:  # Only if we have enough data points
                        plt.figure(figsize=(10, 6))
                        plt.plot(df['Time'], df['Cracked'], label=f"{'Salted' if result['salt'] else 'Unsalted'}")
                        plt.title(f'Cracking Progress: {file} ({attack} attack)')
                        plt.xlabel('Time (seconds)')
                        plt.ylabel('Passwords Cracked')
                        plt.grid(True, linestyle='--', alpha=0.7)
                        plt.legend()
                        plt.savefig(f'{PLOTS_DIR}/{file}_{attack}_{"salted" if result["salt"] else "unsalted"}_progress.png')
                        plt.close()
                        
                        # Attempts vs. Cracked plot
                        plt.figure(figsize=(10, 6))
                        plt.plot(df['Attempts'], df['Cracked'], label=f"{'Salted' if result['salt'] else 'Unsalted'}")
                        plt.title(f'Attempts vs. Success: {file} ({attack} attack)')
                        plt.xlabel('Estimated Attempts')
                        plt.ylabel('Passwords Cracked')
                        plt.grid(True, linestyle='--', alpha=0.7)
                        plt.legend()
                        plt.savefig(f'{PLOTS_DIR}/{file}_{attack}_{"salted" if result["salt"] else "unsalted"}_attempts.png')
                        plt.close()
                except Exception as e:
                    print(f"Error creating progress plots for {result['stats_file']}: {e}")
    
    # Create combined plot for all password sets (dictionary attack)
    plt.figure(figsize=(12, 8))
    files = sorted(set(r['file'] for r in results if r['attack'] == 'dictionary'))
    x = np.arange(len(files))
    width = 0.35
    
    unsalted_times = [next(r['time'] for r in results if r['file'] == f and r['attack'] == 'dictionary' and not r['salt']) for f in files]
    salted_times = [next(r['time'] for r in results if r['file'] == f and r['attack'] == 'dictionary' and r['salt']) for f in files]
    
    plt.bar(x - width/2, unsalted_times, width, label='Unsalted', color='skyblue')
    plt.bar(x + width/2, salted_times, width, label='Salted', color='navy')
    
    plt.xlabel('Password Set')
    plt.ylabel('Time (seconds)')
    plt.title('Dictionary Attack: Time Comparison Across Password Sets')
    plt.xticks(x, [f.replace('_', ' ').title() for f in files])
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/combined_dictionary_time_comparison.png')
    plt.close()
    
    # Create combined plot for all password sets (brute force attack)
    plt.figure(figsize=(12, 8))
    files = sorted(set(r['file'] for r in results if r['attack'] == 'bruteforce'))
    x = np.arange(len(files))
    
    unsalted_times = [next(r['time'] for r in results if r['file'] == f and r['attack'] == 'bruteforce' and not r['salt']) for f in files]
    salted_times = [next(r['time'] for r in results if r['file'] == f and r['attack'] == 'bruteforce' and r['salt']) for f in files]
    
    plt.bar(x - width/2, unsalted_times, width, label='Unsalted', color='salmon')
    plt.bar(x + width/2, salted_times, width, label='Salted', color='darkred')
    
    plt.xlabel('Password Set')
    plt.ylabel('Time (seconds)')
    plt.title('Brute Force Attack: Time Comparison Across Password Sets')
    plt.xticks(x, [f.replace('_', ' ').title() for f in files])
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(f'{PLOTS_DIR}/combined_bruteforce_time_comparison.png')
    plt.close()

def main():
    # Make sure we have password files
    if not os.path.exists('password_sets/timestamp.txt'):
        print("Error: Password files not found. Run the password generation script first.")
        return
    
    # Test both dictionary and brute force attacks on all password sets
    results = []
    
    password_files = [
        'password_sets/lower_alpha.txt',
        'password_sets/full_alpha.txt',
        'password_sets/alphanumeric.txt',
        'password_sets/all_chars.txt'
    ]
    
    for attack_mode in ['dictionary', 'bruteforce']:
        for password_file in password_files:
            # Test unsalted hashed passwords first
            result = run_cracking_test(password_file, use_salt=False, attack_mode=attack_mode)
            results.append(result)
            
            # Then test salted hashed passwords
            result = run_cracking_test(password_file, use_salt=True, attack_mode=attack_mode)
            results.append(result)
    
    # Write summary results
    with open(f'{OUTPUT_DIR}/summary.txt', 'w') as f:
        f.write("Summary of Password Cracking Tests\n")
        f.write("================================\n\n")
        
        for result in results:
            f.write(f"{result['file']} - {result['attack']} attack - {'Salted' if result['salt'] else 'Unsalted'}:\n")
            f.write(f"  Time: {result['time']:.2f} seconds\n")
            f.write(f"  Cracked: {result['cracked']}/{result['total']} ({result['success_rate']*100:.2f}%)\n\n")
    
    # Create plots
    create_plots(results)
    
    print("\nAll tests completed. Results are available in the 'results' directory.")
    print("Plots are available in the 'plots' directory.")

if __name__ == "__main__":
    main()