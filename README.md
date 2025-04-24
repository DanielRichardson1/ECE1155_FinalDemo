# 🔐 Password Cracking Simulations on Various Encryption Techniques

## 📄 Project Overview

This repository contains simulations and supporting code for evaluating the efficacy of various **password-cracking techniques** across different **encryption methods**. This work was done as part of a broader research project exploring how encryption can strengthen password security in the age of IoT.

With the rapid growth of connected devices, online security has never been more critical. Passwords are the first line of defense, but they are often vulnerable to brute-force, dictionary, and other cracking techniques. By studying the interaction between **encryption** and **cracking methods**, we aim to identify which combinations offer the best protection for sensitive user data.

---

## 🔍 Objective

Our goal is to **simulate password cracking attacks** against four common encryption methods and analyze how varying parameters impact the time and effort required to break them. These parameters include:

- Password length  
- Key length  
- Encryption type  
- Cracking technique  
- Character set (alphabetic, alphanumeric, full ASCII, etc)

---

## 📊 Metrics and Analysis

Our simulations produce plots and metrics for:

- **Time to crack vs. Password length**
- **Success rate vs. Character set complexity**
- **Performance comparison between encryption methods**
- **Impact of salting and key length on resistance to attacks**

---

## 🛠️ How to Run

1. Clone the repo  
   ```bash
   git clone https://github.com/danielrichardson1/ECE1155_FinalDemo.git
   cd ECE1155_FinalDemo
   ```

2. Install requirements  
   ```bash
   pip install -r requirements.txt
   ```

3. Run a simulation  
   Each folder includes its own simulation script.

---

## 🤝 Contributors

- Lucas Connell — Symmetric Encryption  
- Julia Koma — Public Key Encryption  
- Daniel Richarson — Hash Encryption  
- William Muckelroy — Salted Hash Encryption
