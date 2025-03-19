import argparse
import subprocess

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout if result.stdout else result.stderr
    except Exception as e:
        return str(e)

def dns_lookup(domain):
    print("[+] Fetching DNS Records...")
    print(run_command(f"nslookup {domain}"))

def whois_lookup(domain):
    print("[+] Performing WHOIS Lookup...")
    print(run_command(f"whois {domain}"))

def port_scan(ip):
    print("[+] Scanning Open Ports...")
    print(run_command(f"nmap -sV {ip}"))

def ssl_info(domain):
    print("[+] Checking SSL Certificate...")
    print(run_command(f"echo | openssl s_client -connect {domain}:443"))

def shodan_recon(domain):
    print("[+] Performing Shodan Recon...")
    print(run_command(f"shodan host {domain}"))

def virus_total_scan(domain):
    print("[+] Scanning on VirusTotal...")
    print(run_command(f"curl -s https://www.virustotal.com/vtapi/v2/url/report?apikey=YOUR_API_KEY&resource={domain}"))

def sql_injection_test(domain):
    print("[+] Testing for SQL Injection...")
    print(run_command(f"sqlmap -u {domain} --batch --level=1"))

def xss_test(domain):
    print("[+] Testing for XSS Vulnerability...")
    print(run_command(f"xsser --url={domain}"))

def open_redirect_test(domain):
    print("[+] Testing for Open Redirect...")
    print(run_command(f"curl -I {domain}/?url=https://evil.com"))

def lfi_test(domain):
    print("[+] Testing for Local File Inclusion (LFI)...")
    print(run_command(f"curl -s {domain}/?file=../../../../etc/passwd"))

def security_headers(domain):
    print("[+] Checking Security Headers...")
    print(run_command(f"curl -I {domain}"))

def run_all(domain, ip):
    print("\n==================== Running All Security Checks ====================")
    dns_lookup(domain)
    whois_lookup(domain)
    port_scan(ip)
    ssl_info(domain)
    shodan_recon(domain)
    virus_total_scan(domain)
    sql_injection_test(domain)
    xss_test(domain)
    open_redirect_test(domain)
    lfi_test(domain)
    security_headers(domain)

def show_help():
    """Displays Help Menu"""
    print("""
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
    """)

def main():
    parser = argparse.ArgumentParser(description="Cyber Security Toolkit", add_help=False)
    parser.add_argument("-d", "--domain", help="Target domain for scanning")
    parser.add_argument("-i", "--ip", help="Target IP for scanning")
    parser.add_argument("--all", action="store_true", help="Run all security checks")
    parser.add_argument("-h", "--help", action="store_true", help="Show help menu")

    args = parser.parse_args()

    if args.help:
        show_help()
    elif args.all and args.domain and args.ip:
        run_all(args.domain, args.ip)
    elif args.domain:
        dns_lookup(args.domain)
        whois_lookup(args.domain)
        ssl_info(args.domain)
        shodan_recon(args.domain)
        virus_total_scan(args.domain)
        sql_injection_test(args.domain)
        xss_test(args.domain)
        open_redirect_test(args.domain)
        lfi_test(args.domain)
        security_headers(args.domain)
    elif args.ip:
        port_scan(args.ip)
    else:
        print("[!] Invalid usage. Use -h or --help for the correct syntax.")

if __name__ == "__main__":
    main()
