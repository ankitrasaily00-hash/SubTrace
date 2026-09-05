import socket
import sys


WORDLIST = "subdomains.txt"


BANNER = r"""
  _____       _ _____
 / ____|     | |_   _|
| (___  _   _| | | |
 \___ \| | | | | | |
 ____) | |_| | | | |
|_____/ \__,_|_| |_|

      SubTrace
  Subdomain Discovery Tool
"""


def load_subdomains():
    try:
        with open(WORDLIST, "r") as file:
            return [
                line.strip()
                for line in file
                if line.strip()
            ]

    except FileNotFoundError:
        print(f"[-] Wordlist not found: {WORDLIST}")
        sys.exit(1)


def find_subdomains(domain):
    subdomains = load_subdomains()
    found = []

    print(f"[*] Target: {domain}")
    print(f"[*] Wordlist: {len(subdomains)} entries\n")

    for subdomain in subdomains:
        hostname = f"{subdomain}.{domain}"

        try:
            ip_address = socket.gethostbyname(hostname)

            found.append((hostname, ip_address))

            print(
                f"[+] {hostname:<30} -> {ip_address}"
            )

        except socket.gaierror:
            pass

    print("\n[*] Scan complete")
    print(f"[*] Found: {len(found)}")

    return found


def main():
    print(BANNER)

    if len(sys.argv) != 2:
        print("Usage:")
        print("  python subtrace.py <domain>")
        print("\nExample:")
        print("  python subtrace.py example.com")
        sys.exit(1)

    domain = sys.argv[1].strip()

    if domain.startswith("http://"):
        domain = domain[7:]

    elif domain.startswith("https://"):
        domain = domain[8:]

    domain = domain.rstrip("/")

    find_subdomains(domain)


if __name__ == "__main__":
    main()