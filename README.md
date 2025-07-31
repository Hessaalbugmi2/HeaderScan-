# 🔐 HeaderScan++

**HeaderScan++** is a lightweight Python tool for automated analysis of HTTP security headers.  
It helps identify missing or misconfigured headers that could expose web applications to attacks.  

Designed with simplicity and speed in mind, it supports batch scanning and customizable risk scoring—making it ideal for both beginners and professionals in cybersecurity.

---

## 🚀 Features

- 🔍 Scans for critical HTTP security headers  
- ⚠️ Assigns risk scores based on missing headers  
- 📁 Batch mode: Scan multiple URLs from a file  
- 🧩 Customizable header profiles via JSON  
- 📦 Lightweight and CLI-friendly  

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/your-username/HeaderScanPP.git
cd HeaderScanPP

pip install -r requirements.txt

🧪 Usage
Scan a single URL:

python headerscanpp.py https://example.com

Scan multiple URLs from a file:

python headerscanpp.py targets.txt

Save results to a JSON or CSV file:

python headerscanpp.py targets.txt -o results.json


📋 Example Output

Scanning: https://example.com
Score: 27 (High)
- Content-Security-Policy: Missing
- Strict-Transport-Security: Missing
+ X-Frame-Options: DENY

🧩 Custom Header Profiles

You can define your own header weights in a JSON file like this:

{
  "Content-Security-Policy": 10,
  "X-Frame-Options": 5,
  "Strict-Transport-Security": 8
}

Then run with your profile:

python headerscanpp.py https://example.com --profile profiles/custom.json

🙋‍♀️ Author

Made with 💻 by Hessa Albaqami

For inquiries, feedback, or contributions – feel free to open an issue or pull request.
