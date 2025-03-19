# Tools


## WAF Bypass & Real IP Finder Tool 

==========================================
||    WAF Bypass & Real IP Finder Tool   ||
==========================================
Usage:
------
python3 script.py -d <domain>

Options:
--------
-d, --domain   Specify the target domain (example.com)
-h, --help     Show this help message and exit

Example:
--------
python3 script.py -d example.com


## Information Tools

==========================================
||         Cyber Security Toolkit       ||
==========================================

Usage:
------
python3 security_tool.py -d <domain> -i <ip> --all

Options:
--------
-d, --domain      Target domain for scanning (example.com)
-i, --ip          Target IP address for scanning (192.168.1.1)
--all             Run all security checks on the target
-h, --help        Show this help message and exit

Features:
---------
1. DNS Lookup
2. WHOIS Lookup
3. Open Port Scanning (Nmap)
4. SSL Certificate Analysis
5. Shodan Recon
6. VirusTotal Scan
7. SQL Injection Test (SQLMap)
8. XSS Vulnerability Test
9. Open Redirect Test
10. Local File Inclusion (LFI) Test
11. Security Headers Check

Examples:
---------
1️⃣ Basic domain scan:
    python3 security_tool.py -d example.com

2️⃣ Scan an IP for open ports:
    python3 security_tool.py -i 192.168.1.1

3️⃣ Run all available scans:
    python3 security_tool.py -d example.com -i 192.168.1.1 --all
