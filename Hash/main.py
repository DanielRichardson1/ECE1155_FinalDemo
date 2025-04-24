import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from HashString import hash_string
from CrackHash import crack_password_bf, crack_password_dict

# Password sets
numeric_passwords = [
    "123",
    "748",
    "1234",
    "4781",
    "12345",
    "78942",
    "123456",
    "098761"
]

alphatic_lowercase_passwords = [
    "abc",
    "jfm",
    "pass",
    "kjlf",
    "xxxxx",
    "fbaio",
    "secret",
    "jklcxp"
]

lower_alphabetic_numeric_passwords = [
    "hi1",
    "4oh",
    "abc1",
    "52kn",
    "pass1",
    "o2i87",
    "xxxxx1",
    "56ho1j"
]

full_alphabetic_passwords = [
    "AbC",
    "hoK",
    "Pass",
    "hFJa",
    "xXxXx",
    "jmKoP",
    "Secret",
    "GnFhAO"
]


def categorize_passwords():
    """
    Group passwords by length and category for analysis.
    """
    password_data = []
    
    for password in numeric_passwords:
        password_data.append({
            "password": password,
            "category": "numeric",
            "length": len(password)
        })
    
    for password in alphatic_lowercase_passwords:
        password_data.append({
            "password": password,
            "category": "lowercase",
            "length": len(password)
        })
    
    for password in lower_alphabetic_numeric_passwords:
        password_data.append({
            "password": password,
            "category": "lowercase_numeric",
            "length": len(password)
        })
    
    for password in full_alphabetic_passwords:
        password_data.append({
            "password": password,
            "category": "full_alphabetic",
            "length": len(password)
        })
    
    return password_data

def create_visualizations(bf_results, dict_results, hash_algorithms, categories, lengths):
    """
    Create and save visualizations of the password cracking results.
    """
    # 1. Attack success rate by algorithm (both methods)
    plt.figure(figsize=(12, 8))
    x = np.arange(len(hash_algorithms))
    width = 0.35
    
    bf_success_rates = [bf_results["success_rate"][algo] for algo in hash_algorithms]
    dict_success_rates = [dict_results["success_rate"][algo] for algo in hash_algorithms]
    
    plt.bar(x - width/2, bf_success_rates, width, label='Brute Force')
    plt.bar(x + width/2, dict_success_rates, width, label='Dictionary')
    
    plt.xlabel('Hashing Algorithm')
    plt.ylabel('Success Rate (%)')
    plt.title('Attack Success Rate by Hashing Algorithm')
    plt.xticks(x, [algo.upper() for algo in hash_algorithms])
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add success rate labels
    for i, v in enumerate(bf_success_rates):
        plt.text(i - width/2, v + 1, f'{v:.1f}%', ha='center')
    for i, v in enumerate(dict_success_rates):
        plt.text(i + width/2, v + 1, f'{v:.1f}%', ha='center')
    
    plt.tight_layout()
    plt.savefig('attack_success_rate.png')
    plt.close()
    
    # 2. Brute Force Attack Success Rate (Heat Map)
    plt.figure(figsize=(10, 8))
    heatmap_data = bf_results["heatmap_data"]
    
    ax = sns.heatmap(
        heatmap_data, 
        annot=True, 
        fmt=".1f", 
        cmap="YlGnBu", 
        xticklabels=[algo.upper() for algo in hash_algorithms],
        yticklabels=categories,
        vmin=0,
        vmax=100
    )
    
    plt.xlabel('Hashing Algorithm')
    plt.ylabel('Password Category')
    plt.title('Brute Force Attack Success Rate (%)')
    plt.tight_layout()
    plt.savefig('brute_force_heatmap.png')
    plt.close()
    
    # 3. Password cracking time vs length (both methods)
    plt.figure(figsize=(14, 7))
    
    # Prepare data
    bf_times_by_length = []
    dict_times_by_length = []
    
    for length in lengths:
        if bf_results["time_by_length"][length]:
            bf_times_by_length.append(np.mean(bf_results["time_by_length"][length]))
        else:
            bf_times_by_length.append(0)
            
        if dict_results["time_by_length"][length]:
            dict_times_by_length.append(np.mean(dict_results["time_by_length"][length]))
        else:
            dict_times_by_length.append(0)
    
    plt.subplot(1, 2, 1)
    plt.plot(lengths, bf_times_by_length, 'o-', label='Brute Force')
    for i, txt in enumerate(bf_times_by_length):
        plt.annotate(f'{txt:.2f}s', (lengths[i], txt), xytext=(5, 5), textcoords='offset points')
    plt.xlabel('Password Length')
    plt.ylabel('Average Cracking Time (seconds)')
    plt.title('Brute Force: Time vs Password Length')
    plt.grid(True, alpha=0.3)
    
    plt.subplot(1, 2, 2)
    plt.plot(lengths, dict_times_by_length, 'o-', color='orange', label='Dictionary')
    for i, txt in enumerate(dict_times_by_length):
        plt.annotate(f'{txt:.2f}s', (lengths[i], txt), xytext=(5, 5), textcoords='offset points')
    plt.xlabel('Password Length')
    plt.ylabel('Average Cracking Time (seconds)')
    plt.title('Dictionary: Time vs Password Length')
    plt.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('cracking_time_vs_length.png')
    plt.close()
    
    # 4. Password cracking time vs category (both methods)
    plt.figure(figsize=(14, 7))
    
    # Prepare data
    bf_times_by_category = []
    dict_times_by_category = []
    
    for category in categories:
        if bf_results["time_by_category"][category]:
            bf_times_by_category.append(np.mean(bf_results["time_by_category"][category]))
        else:
            bf_times_by_category.append(0)
            
        if dict_results["time_by_category"][category]:
            dict_times_by_category.append(np.mean(dict_results["time_by_category"][category]))
        else:
            dict_times_by_category.append(0)
    
    plt.subplot(1, 2, 1)
    x = np.arange(len(categories))
    plt.bar(x, bf_times_by_category)
    plt.xlabel('Password Category')
    plt.ylabel('Average Cracking Time (seconds)')
    plt.title('Brute Force: Time vs Password Category')
    plt.xticks(x, categories, rotation=45)
    for i, v in enumerate(bf_times_by_category):
        plt.text(i, v + 0.1, f'{v:.2f}s', ha='center')
    
    plt.subplot(1, 2, 2)
    plt.bar(x, dict_times_by_category, color='orange')
    plt.xlabel('Password Category')
    plt.ylabel('Average Cracking Time (seconds)')
    plt.title('Dictionary: Time vs Password Category')
    plt.xticks(x, categories, rotation=45)
    for i, v in enumerate(dict_times_by_category):
        plt.text(i, v + 0.1, f'{v:.2f}s', ha='center')
    
    plt.tight_layout()
    plt.savefig('cracking_time_vs_category.png')
    plt.close()
    
    print("\nVisualizations saved:")
    print("1. attack_success_rate.png")
    print("2. brute_force_heatmap.png")
    print("3. cracking_time_vs_length.png")
    print("4. cracking_time_vs_category.png")

def simulate_password_cracking():
    """
    Runs the password cracking simulation
    """
    password_data = categorize_passwords()
    hash_algorithms = ["md5", "sha256", "bcrypt", "argon2"]
    categories = ["numeric", "lowercase", "lowercase_numeric", "full_alphabetic"]
    lengths = [3, 4, 5, 6]
    
    # Results data structures
    bf_results = {
        "success_rate": {algo: 0 for algo in hash_algorithms},
        "time_by_length": {length: [] for length in lengths},
        "time_by_category": {cat: [] for cat in categories},
        "heatmap_data": np.zeros((len(categories), len(hash_algorithms)))
    }
    
    dict_results = {
        "success_rate": {algo: 0 for algo in hash_algorithms},
        "time_by_length": {length: [] for length in lengths},
        "time_by_category": {cat: [] for cat in categories}
    }
    
    # Track attempt counts for rate calculations
    bf_attempts = {algo: 0 for algo in hash_algorithms}
    dict_attempts = {algo: 0 for algo in hash_algorithms}
    
    # Counter for progress tracking
    total_tests = len(password_data) * len(hash_algorithms)
    current_test = 0
    
    print("Starting password cracking simulation...")
    
    # Run tests for each password with each algorithm
    for pwd_info in password_data:
        password = pwd_info["password"]
        category = pwd_info["category"]
        length = pwd_info["length"]
        
        # Get category index for heatmap
        cat_idx = categories.index(category)
        
        for i, algo in enumerate(hash_algorithms):
            current_test += 1
            print(f"Testing {current_test}/{total_tests}: '{password}' with {algo}")
            
            # Hash the password
            hashed, _ = hash_string(password, algo)
            
            # Try optimized brute force with known charset
            bf_attempts[algo] += 1
            bf_success, bf_time, bf_cracked = crack_password_bf(hashed, algo, category)
            
            # Track brute force results
            if bf_success:
                bf_results["success_rate"][algo] += 1
                bf_results["time_by_length"][length].append(bf_time)
                bf_results["time_by_category"][category].append(bf_time)
                bf_results["heatmap_data"][cat_idx][i] += 1
            
            # Try dictionary attack
            dict_attempts[algo] += 1
            dict_success, dict_time, dict_cracked = crack_password_dict(hashed, algo)
            
            # Track dictionary results
            if dict_success:
                dict_results["success_rate"][algo] += 1
                dict_results["time_by_length"][length].append(dict_time)
                dict_results["time_by_category"][category].append(dict_time)
    
    # Calculate success rates
    for algo in hash_algorithms:
        if bf_attempts[algo] > 0:
            bf_results["success_rate"][algo] = (bf_results["success_rate"][algo] / bf_attempts[algo]) * 100
        
        if dict_attempts[algo] > 0:
            dict_results["success_rate"][algo] = (dict_results["success_rate"][algo] / dict_attempts[algo]) * 100
    
    # Normalize heatmap data for percentages
    for i in range(len(categories)):
        row_total = sum([bf_attempts[algo] / len(categories) for algo in hash_algorithms])
        if row_total > 0:
            for j in range(len(hash_algorithms)):
                bf_results["heatmap_data"][i][j] = (bf_results["heatmap_data"][i][j] / (bf_attempts[hash_algorithms[j]] / len(categories))) * 100
    
    # Generate visualizations
    create_visualizations(bf_results, dict_results, hash_algorithms, categories, lengths)
    
    return bf_results, dict_results

# Run the simulation
if __name__ == "__main__":
    bf_results, dict_results = simulate_password_cracking()