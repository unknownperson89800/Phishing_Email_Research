#  Phishing Email Detection Tool

This repository contains a Python-based phishing email detection tool and a set of sample phishing `.eml` emails for educational and testing purposes.

## 📁 Repository Structure

```
 phishing-email-detector/
├── Phishing_Email_Detaction.py     # Main CLI tool to scan emails
├── email_parsar.py                 # Parses .eml files to extract headers, URLs, domains, and IPs
├── api_clients.py                  # Connects to VirusTotal, AbuseIPDB, URLScan for threat analysis
├── simple_main.py                  # Minimal starter entry point (optional)
├── simple_config.py                # Config file for API keys and constants
├──  phishing_emails/             # Sample phishing emails in .eml format
│   ├── 1_Information_Gathering.eml
│   ├── 2_Credential_Harvesting.eml
│   └── ... etc.
├── requirements.txt                # Python dependencies
└── README.md                       # Project documentation
```

## 🚀 Features

- Parses and scans `.eml` files for malicious content
- Extracts and checks:
  -  All URLs
  -  Domains & IPs
  -  Email headers (From, To, Subject, DKIM if needed)
- Verifies via:
  -  VirusTotal API
  -  URLScan.io
  -  AbuseIPDB for IP reputation
- Generates  detailed Markdown reports with verdicts

##  Sample Emails Included

Includes 7 common phishing techniques as `.eml` samples:
1. Information Gathering
2. Credential Harvesting
3. Malware Delivery
4. Spear Phishing
5. Whaling
6. Vishing
7. Quishing

## 🛠 Setup

```bash
git clone https://github.com/yourusername/phishing-email-detector.git
cd phishing-email-detector
pip install -r requirements.txt
```

##  Add API Keys

Edit your `api_clients.py` file and replace:
```python
VT_API = "your_virustotal_api_key"
URLSCAN_API = "your_urlscan_api_key"
ABUSEIPDB_API = "your_abuseipdb_api_key"
```

##  Usage

```bash
python3 Phishing_Email_Detaction.py phishing_emails/2_Credential_Harvesting.eml --output report.md
```

##  Sample Output

- URL results: VirusTotal & URLScan verdicts
- IP results: AbuseIPDB reputation score
- Verdict: **Phishing** ✅ or ❌

##  License

For educational use only. Do not use for malicious purposes.

---

**Author:** Patel Om  
**Internship:** SOC Analyst 15-Day Project  
