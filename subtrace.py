import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver


WORDLIST = "subdomains.txt"
DEFAULT_WORKERS = 10

RECORD_TYPES = ["A", "CNAME", "MX", "NS", "TXT"]


BANNER = r"""
  _____       _ _____
 / ____|     | |_   _|
| (___  _   _| | | |
 \___ \| | | | | | |
 ____) | |_| | | | |
|_____/ \__,_|_| |_|

      SubTrace
  DNS Reconnaissance Tool
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


def resolve_record(hostname, record_type):
    records = []

    try:
        answers = dns.resolver.resolve(
            hostname,
            record_type
        )

        for answer in answers:
            records.append(
                (record_type, str(answer))
            )

    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        pass

    return records


def resolve_dns(hostname):
    records = []

    for record_type in RECORD_TYPES:
        records.extend(
            resolve_record(
                hostname,
                record_type
            )
        )

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
    print(f"[*] Workers: {workers}")
    print(f"[*] Records: {', '.join(RECORD_TYPES)}\n")

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

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

            if not records:
                continue

            found.append(
                (hostname, records)
            )

            print(f"\n[+] {hostname}")

            for record_type, value in records:
                record_count += 1

                print(
                    f"    {record_type:<6} -> {value}"
                )

    print("\n[*] Scan complete")
    print(f"[*] Subdomains found: {len(found)}")
    print(f"[*] DNS records found: {record_count}")

    return found


def save_results(results, output_file):
    try:
        with open(output_file, "w") as file:

            for hostname, records in results:

                file.write(
                    f"{hostname}\n"
                )

                for record_type, value in records:

                    file.write(
                        f"    {record_type} -> {value}\n"
                    )

                file.write("\n")

        print(
            f"[*] Results saved to: {output_file}"
        )

    except OSError as error:
        print(
            f"[-] Could not save results: {error}"
        )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "SubTrace - Lightweight DNS "
            "reconnaissance tool"
        )
    )

    parser.add_argument(
        "domain",
        help="Target domain"
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        default=WORDLIST,
        help=(
            f"Subdomain wordlist "
            f"(default: {WORDLIST})"
        )
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Save results to a file"
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=DEFAULT_WORKERS,
        help=(
            "Number of concurrent DNS lookups "
            f"(default: {DEFAULT_WORKERS})"
        )
    )

    args = parser.parse_args()

    if args.threads < 1:
        parser.error(
            "threads must be at least 1"
        )

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