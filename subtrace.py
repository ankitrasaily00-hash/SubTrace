
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver


WORDLIST = "subdomains.txt"
DEFAULT_WORKERS = 10


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


def resolve_dns(hostname):
    records = []

    try:
        answers = dns.resolver.resolve(hostname, "A")

        for answer in answers:
            records.append(("A", str(answer)))

    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        pass

    try:
        answers = dns.resolver.resolve(hostname, "CNAME")

        for answer in answers:
            records.append(("CNAME", str(answer)))

    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        pass

    return hostname, records


def scan_subdomain(domain, subdomain):
    hostname = f"{subdomain}.{domain}"

    try:
        return resolve_dns(hostname)

    except Exception:
        return hostname, []


def find_subdomains(domain, wordlist, workers):
    subdomains = load_subdomains(wordlist)
    found = []
    record_count = 0

    if not subdomains:
        return found

    print(f"[*] Target: {domain}")
    print(f"[*] Wordlist: {len(subdomains)} entries")
    print(f"[*] Workers: {workers}\n")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        tasks = [
            executor.submit(
                scan_subdomain,
                domain,
                subdomain
            )
            for subdomain in subdomains
        ]

        for task in as_completed(tasks):
            hostname, records = task.result()

            if records:
                found.append((hostname, records))

                for record_type, value in records:
                    record_count += 1

                    print(
                        f"[+] {hostname:<35} "
                        f"{record_type:<6} -> {value}"
                    )

    print("\n[*] Scan complete")
    print(f"[*] Subdomains found: {len(found)}")
    print(f"[*] DNS records found: {record_count}")

    return found


def save_results(results, output_file):
    try:
        with open(output_file, "w") as file:
            for hostname, records in results:
                for record_type, value in records:
                    file.write(
                        f"{hostname} "
                        f"{record_type} -> {value}\n"
                    )

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

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Number of concurrent DNS lookups (default: {DEFAULT_WORKERS})"
    )

    args = parser.parse_args()

    if args.threads < 1:
        parser.error("threads must be at least 1")

    domain = args.domain.strip()

    if domain.startswith("http://"):
        domain = domain[7:]

    elif domain.startswith("https://"):
        domain = domain[8:]

    domain = domain.rstrip("/")

    print(BANNER)

    results = find_subdomains(
        domain,
        args.wordlist,
        args.threads
    )

    if args.output and results:
        save_results(
            results,
            args.output
        )


if __name__ == "__main__":
    main()

