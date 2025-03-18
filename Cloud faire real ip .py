import requests
import dns.resolver
import shodan
import subprocess

def find_real_ip(domain):
    print("""
    [*] WAF Bypass & Real IP Finder
    --------------------------------
    1. Checks historical DNS records
    2. Finds subdomains and their IPs
    3. Uses Shodan to search leaked IPs
    """)
    
    print(f"[*] Checking historical DNS records for {domain}...")
    try:
        result = subprocess.run(["dig", domain, "A"], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error: {e}")
    
    print(f"[*] Checking subdomains for {domain}...")
    subdomains = ["mail", "ftp", "direct", "cpanel", "webmail"]
    for sub in subdomains:
        try:
            full_domain = f"{sub}.{domain}"
            answer = dns.resolver.resolve(full_domain, "A")
            for ip in answer:
                print(f"[+] Found potential real IP: {ip}")
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            continue
    
    print(f"[*] Searching in Shodan for {domain}...")
    SHODAN_API_KEY = "your_shodan_api_key_here"
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.search(f"hostname:{domain}")
        for result in results["matches"]:
            print(f"[+] Possible real IP: {result['ip_str']}")
    except Exception as e:
        print(f"Shodan error: {e}")
    
if __name__ == "__main__":
    print("""
    Usage:
    ------
    Enter the target domain to find its real IP.
    Example: example.com
    """)
    target_domain = input("Enter target domain: ")
    find_real_ip(target_domain)
