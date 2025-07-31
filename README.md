# 🔐 HeaderScan++

**HeaderScan++** is a lightweight Python tool for automated detection and risk assessment of missing or misconfigured HTTP security headers.

It helps identify common misconfigurations that may expose web applications to client-side attacks like XSS, clickjacking, or protocol downgrade.  
Designed with speed and clarity in mind, it's ideal for cybersecurity students, professionals, and DevSecOps teams.

---

## 🚀 Features

- 🔍 Scans for critical HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
- ⚠️ Assigns customizable risk scores based on header presence and configuration
- 📁 Supports batch scanning of multiple URLs from file
- 🧩 Accepts custom header profiles via JSON
- 📦 Lightweight, fast, and CLI-friendly

---

## 📦 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/hessaalbugmi2/HeaderScanPP.git
cd HeaderScanPP
pip install -r requirements.txt

Usage
🔹 Scan a single URL:

python headerscanpp.py https://example.com

🔹 Scan multiple URLs from a file:

python headerscanpp.py targets.txt

🔹 Save results to JSON or CSV:

python headerscanpp.py targets.txt -o results.json

📋 Example Output

Scanning: https://example.com
Score: 27 (High)
- Content-Security-Policy: Missing
- Strict-Transport-Security: Missing
+ X-Frame-Options: SAMEORIGIN

🧩 Custom Header Profiles

Define your own header weights in a JSON file like this:

{
  "Content-Security-Policy": 10,
  "X-Frame-Options": 5,
  "Strict-Transport-Security": 8
}

Then run the tool with your custom profile:

python headerscanpp.py https://example.com --profile profiles/custom.json

Author

Made with 💻 by Hessa Albaqami
For inquiries, suggestions, or contributions – feel free to open an issue or a pull request.

