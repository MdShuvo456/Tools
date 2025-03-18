import os
import requests
import hashlib
import socket
import argparse

from bs4 import BeautifulSoup

# 🛠️ Function to find subdomains
def subdomain_finder(domain):
    print("[+] Finding Subdomains...")
    subdomains = ["www", "mail", "ftp", "dev", "test"]
    found = []

    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            found.append(subdomain)
        except socket.gaierror:
            pass

    return found


# 🛠️ Directory Bruteforce with Timeout and SSL Fix
def dir_bruteforce(url):
    print("[+] Bruteforcing Directories...")

    wordlist = ["admin", "login", "dashboard", "uploads"]
    found = []

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    for word in wordlist:
        test_url = f"{url}/{word}"

        try:
            response = requests.get(test_url, headers=headers, timeout=5, verify=False)  # ✅ Timeout + SSL Off
            if response.status_code == 200:
                found.append(test_url)
        except requests.exceptions.RequestException as e:
            print(f"[-] Error: {e}")  # ✅ Error Handle

    return found


# 🛠️ Port Scanner (Optimized)
def port_scan(ip):
    print("[+] Scanning Ports...")
    open_ports = []

    for port in range(1, 1025):  # Faster Scanning (1-1024)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)

        if s.connect_ex((ip, port)) == 0:
            open_ports.append(port)

        s.close()

    return open_ports


# 🛠️ SQL Injection Scanner (Improved)
def sql_injection_scanner(url):
    print("[+] Checking for SQL Injection...")

    payloads = ["' OR '1'='1' -- ", "' UNION SELECT null,null -- ", "'; DROP TABLE users; --"]
    
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        
        try:
            response = requests.get(test_url, timeout=5, verify=False)
            if any(error in response.text.lower() for error in ["sql", "syntax", "mysql", "error"]):
                return True
        except requests.exceptions.RequestException:
            pass

    return False


# 🛠️ XSS Scanner (Updated)
def xss_scanner(url):
    print("[+] Checking for XSS Vulnerability...")

    payloads = ['<script>alert("XSS")</script>', '" onmouseover="alert(\'XSS\')"']
    
    for payload in payloads:
        test_url = f"{url}?q={payload}"

        try:
            response = requests.get(test_url, timeout=5, verify=False)
            if payload in response.text:
                return True
        except requests.exceptions.RequestException:
            pass

    return False


# 🛠️ Hash Cracker (Supports MD5, SHA1, SHA256, SHA512)
def hash_cracker(hash_value, wordlist_file):
    print("[+] Cracking Hash...")

    hash_types = {
        32: hashlib.md5,
        40: hashlib.sha1,
        64: hashlib.sha256,
        128: hashlib.sha512
    }

    hash_length = len(hash_value)
    if hash_length not in hash_types:
        print("[-] Unsupported Hash Type!")
        return None

    hash_function = hash_types[hash_length]

    with open(wordlist_file, "r") as file:
        for word in file:
            word = word.strip()
            if hash_function(word.encode()).hexdigest() == hash_value:
                return word

    return None


# 🛠️ Show Help Menu
def show_help():
    help_text = """
    Usage: python tool.py [OPTIONS]
    
    Options:
      --domain DOMAIN      Find subdomains of a domain
      --url URL            Scan a website for directories, SQLi, and XSS
      --ip IP              Scan an IP for open ports
      --hash HASH          Crack a hash value (MD5, SHA1, SHA256, SHA512)
      --wordlist FILE      Path to wordlist for hash cracking
      --help               Show this help message and exit
    """
    print(help_text)


# 🚀 Main Execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("--domain", help="Find subdomains of a domain")
    parser.add_argument("--url", help="Scan a website for vulnerabilities")
    parser.add_argument("--ip", help="Scan an IP for open ports")
    parser.add_argument("--hash", help="Crack a hash value")
    parser.add_argument("--wordlist", help="Path to wordlist for hash cracking")
    parser.add_argument("--help", action="store_true", help="Show help message")

    args = parser.parse_args()

    if args.help:
        show_help()
    elif args.domain:
        print("Subdomains:", subdomain_finder(args.domain))
    elif args.url:
        print("Directories Found:", dir_bruteforce(args.url))
        print("SQL Injection Found:", sql_injection_scanner(args.url))
        print("XSS Vulnerability Found:", xss_scanner(args.url))
    elif args.ip:
        print("Open Ports:", port_scan(args.ip))
    elif args.hash and args.wordlist:
        cracked = hash_cracker(args.hash, args.wordlist)
        print("Cracked Password:", cracked if cracked else "Not Found")
    else:
        show_help()
