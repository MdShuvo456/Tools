import os
import requests
import subprocess
import hashlib
from bs4 import BeautifulSoup
import socket
import argparse

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

def dir_bruteforce(url):
    print("[+] Bruteforcing Directories...")
    wordlist = ["admin", "login", "dashboard", "uploads"]
    found = []
    for word in wordlist:
        test_url = f"{url}/{word}"
        response = requests.get(test_url)
        if response.status_code == 200:
            found.append(test_url)
    return found

def port_scan(ip):
    print("[+] Scanning Ports...")
    open_ports = []
    for port in range(1, 65536):  # Scanning all ports (1-65535)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((ip, port)) == 0:
            open_ports.append(port)
        s.close()
    return open_ports

def sql_injection_scanner(url):
    print("[+] Checking for SQL Injection...")
    payload = "' OR '1'='1"  # Basic SQLi Payload
    test_url = f"{url}?id={payload}"
    response = requests.get(test_url)
    if "sql" in response.text.lower():
        return True
    return False

def xss_scanner(url):
    print("[+] Checking for XSS Vulnerability...")
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?q={payload}"
    response = requests.get(test_url)
    if payload in response.text:
        return True
    return False

def hash_cracker(hash_value, wordlist_file):
    print("[+] Cracking Hash...")
    with open(wordlist_file, "r") as file:
        for word in file:
            word = word.strip()
            if hashlib.md5(word.encode()).hexdigest() == hash_value:
                return word
    return None

def show_help():
    help_text = """
    Usage: python tool.py [OPTIONS]
    
    Options:
      --domain DOMAIN      Find subdomains of a domain
      --url URL            Scan a website for directories, SQLi, and XSS
      --ip IP              Scan an IP for open ports
      --hash HASH          Crack a hash value (MD5)
      --wordlist FILE      Path to wordlist for hash cracking
      --help               Show this help message and exit
    """
    print(help_text)

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
