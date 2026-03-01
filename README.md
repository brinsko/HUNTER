# ⚔ Open Redirect Hunter

> Offensive Security Automation Framework  
> Author: **Brinsko**  
> Version: 1.0  

---

## 🔥 Overview

**Hunter** is a modular reconnaissance and vulnerability automation framework designed to detect:

- Open Redirect vulnerabilities
- Parameter-based attack surfaces
- Historical URL exposure
- Subdomain expansion targets

It integrates powerful industry tools into a clean, automated workflow.

Built for security researchers, bug bounty hunters, and red teamers.

---

## ⚙ Installation

### 1️⃣ Clone the repository

git clone https://github.com/brinsko/HUNTER.git
cd HUNTER
python3 -m venv venv
source venv/bin/activate 
chmod +x setup.sh
./setup.sh
nano domains.txt
./or_hunter.sh
