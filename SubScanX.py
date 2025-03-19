import requests
import threading
import argparse

# Function to check URLs
def check_url(target, wordlist, mode):
    with open(wordlist, "r") as file:
        words = file.read().splitlines()
    
    for word in words:
        if mode == "dir":
            url = f"{target}/{word}"
        elif mode == "sub":
            url = f"http://{word}.{target}"
        
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                print(f"[+] Found: {url} - Status: {response.status_code}")
        except requests.ConnectionError:
            pass

# Main function
def main():
    parser = argparse.ArgumentParser(description="Simple Gobuster Clone")
    parser.add_argument("-u", "--url", required=True, help="Target URL (example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-m", "--mode", choices=["dir", "sub"], required=True, help="Mode: 'dir' for directory busting, 'sub' for subdomain enumeration")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=3, help="Request timeout in seconds (default: 3)")
    args = parser.parse_args()
    
    print("\n--- Gobuster Clone Help ---")
    print("Usage:")
    print("  python gobuster_clone.py -u http://example.com -w wordlist.txt -m dir")
    print("  python gobuster_clone.py -u example.com -w subdomains.txt -m sub")
    print("\nOptions:")
    print("  -u, --url       Target URL (example.com)")
    print("  -w, --wordlist  Path to wordlist file")
    print("  -m, --mode      Mode: 'dir' (directory busting) or 'sub' (subdomain enumeration)")
    print("  -t, --threads   Number of threads (default: 10)")
    print("  --timeout       Request timeout in seconds (default: 3)")
    print("---------------------------\n")
    
    thread = threading.Thread(target=check_url, args=(args.url, args.wordlist, args.mode))
    thread.start()
    thread.join()

if __name__ == "__main__":
    main()
