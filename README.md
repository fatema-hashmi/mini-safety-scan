- #  Mini Safety Scan

A tiny Python script that scans common ports on a host you own and prints plain-English risks + fixes.  

- ## 🚀 How to Run (Windows)
  •  python -m venv .venv
  
  •  .\.venv\Scripts\activate
  
  •  python scan.py --host 127.0.0.1 --top 20 --out report.txt

- ## 🚀 How to Run (Mac/Linux)
   • python3 -m venv .venv
  
   • source .venv/bin/activate
  
   • python3 scan.py --host 127.0.0.1 --top 20 --out report.txt

Open **report.txt** to see the results.  

- ## 🔍 What It Checks
• A small set of widely-used ports (web, SSH, RDP, DB, mail…)  
• For each open port, it explains:  
   - Why the service exists  
   - Basic risk (e.g., clear-text auth, brute-force)  
   - Simple fix (e.g., disable legacy service, use HTTPS, restrict access)  

No external packages required — just Python 
