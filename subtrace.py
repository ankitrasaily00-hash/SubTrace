import argparse
import socket


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


def load_subdomains(wordlist):
    try:
        with open(wordlist, "r") as file:
            return [
                line.strip()
                for line in file
                if line.strip()
            ]

    except FileNotFoundError:
        print(f"[-] Wordlist not found: {wordlist}")
        return []


def find_subdomains(domain, wordlist):
    subdomains = load_subdomains(wordlist)
    found = []

    print(f"[*] Target: {domain}")
    print(f"[*] Wordlist: {len(subdomains)} entries\n")

    for subdomain in subdomains:
        hostname = f"{subdomain}.{domain}"

        try:
            ip_address = socket.gethostbyname(hostname)

            found.append((hostname, ip_address))

            print(
                f"[+] {hostname:<35} -> {ip_address}"
            )

        except socket.gaierror:
            pass

    print("\n[*] Scan complete")
    print(f"[*] Found: {len(found)}")

    return found


def save_results(results, output_file):
    try:
        with open(output_file, "w") as file:
            for hostname, ip_address in results:
                file.write(f"{hostname} -> {ip_address}\n")

        print(f"[*] Results saved to: {output_file}")

    except OSError as error:
        print(f"[-] Could not save results: {error}")


def main():
    parser = argparse.ArgumentParser(
        description="SubTrace - Lightweight subdomain discovery tool"
    )

    parser.add_argument(
        "domain",
        help="Target domain"
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        default=WORDLIST,
        help=f"Subdomain wordlist (default: {WORDLIST})"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Save discovered subdomains to a file"
    )

    args = parser.parse_args()

    domain = args.domain.strip()

    if domain.startswith("http://"):
        domain = domain[7:]

    elif domain.startswith("https://"):
        domain = domain[8:]

    domain = domain.rstrip("/")

    print(BANNER)

    results = find_subdomains(
        domain,
        args.wordlist
    )

    if args.output and results:
        save_results(results, args.output)


if __name__ == "__main__":
    main()