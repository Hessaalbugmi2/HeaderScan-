# HeaderScan++

**HeaderScan++** is a lightweight Python tool for automated analysis of HTTP security headers. It helps identify missing or misconfigured headers that could expose web applications to attacks. Designed with simplicity and speed in mind, it supports batch scanning and customizable risk scoring, making it ideal for both beginners and professionals in cybersecurity.

---

## 🚀 Features

- 🔍 Scans for critical HTTP security headers
- ⚠️ Assigns risk scores based on missing headers
- 📁 Batch mode: scan multiple URLs from a file
- ⚙️ Customizable profiles via JSON
- 📦 Lightweight and CLI-friendly

---

## 📦 Installation

1. **Clone the repository:**

```bash
git clone https://github.com/your-username/HeaderScanPP.git
cd HeaderScanPP

Install required packages:
bash
Copy
Edit
pip install -r requirements.txt

📋 Example Output

python headerscanpp.py --url https://example.com

Output:
https://example.com
[-] Missing headers: Content-Security-Policy, X-Frame-Options
[!] Risk Score: 7.5/10

🧩 Custom Header Profiles
You can define your own header checks in a JSON file like this:
{
  "Content-Security-Policy": 2.0,
  "X-Frame-Options": 1.5,
  "Strict-Transport-Security": 1.0
}

Then run:
python headerscanpp.py --url https://example.com --profile profiles/custom.json

🙋‍♀️ Author
Made with 💻 by Hessa Albaqami

For inquiries, feedback, or contributions – feel free to open an issue or reach out.



