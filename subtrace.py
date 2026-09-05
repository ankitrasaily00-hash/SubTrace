import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver
import requests


WORDLIST = "subdomains.txt"
DEFAULT_WORKERS = 10
REQUEST_TIMEOUT = 5

RECORD_TYPES = ["A", "CNAME", "MX", "NS", "TXT"]


BANNER = r"""
  _____       _ _____
 / ____|     | |_   _|
| (___  _   _| | | |
 \___ \| | | | | | |
 ____) | |_| | | | |
|_____/ \__,_|_| |_|

      SubTrace
  DNS + HTTP Reconnaissance Tool
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


def check_http(hostname):
    urls = [
        f"https://{hostname}",
        f"http://{hostname}"
    ]

    for url in urls:
        try:
            response = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={
                    "User-Agent": "SubTrace/6.0"
                }
            )

            server = response.headers.get(
                "Server",
                "Unknown"
            )

            title = "N/A"

            if response.text:
                lower_text = response.text.lower()

                start = lower_text.find("<title>")

                if start != -1:
                    end = lower_text.find(
                        "</title>",
                        start
                    )

                    if end != -1:
                        title = response.text[
                            start + 7:end
                        ].strip()

            return {
                "url": response.url,
                "status": response.status_code,
                "title": title,
                "server": server
            }

        except requests.RequestException:
            continue

    return None


def scan_subdomain(domain, subdomain):
    hostname = f"{subdomain}.{domain}"

    try:
        hostname, records = resolve_dns(
            hostname
        )

        if not records:
            return hostname, [], None

        http_info = check_http(hostname)

        return hostname, records, http_info

    except Exception:
        return hostname, [], None


def find_subdomains(domain, wordlist, workers):
    subdomains = load_subdomains(wordlist)

    found = []
    record_count = 0
    http_count = 0

    if not subdomains:
        return found

    print(f"[*] Target: {domain}")
    print(f"[*] Wordlist: {len(subdomains)} entries")
    print(f"[*] Workers: {workers}")
    print(f"[*] DNS Records: {', '.join(RECORD_TYPES)}")
    print("[*] HTTP Detection: HTTPS + HTTP\n")

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
            hostname, records, http_info = (
                task.result()
            )

            if not records:
                continue

            found.append(
                (hostname, records, http_info)
            )

            print(f"\n[+] {hostname}")

            for record_type, value in records:
                record_count += 1

                print(
                    f"    {record_type:<6} -> {value}"
                )

            if http_info:
                http_count += 1

                print(
                    f"    HTTP   -> "
                    f"{http_info['status']} "
                    f"{http_info['url']}"
                )

                print(
                    f"    Title  -> "
                    f"{http_info['title']}"
                )

                print(
                    f"    Server -> "
                    f"{http_info['server']}"
                )

            else:
                print(
                    "    HTTP   -> No web service detected"
                )

    print("\n[*] Scan complete")
    print(
        f"[*] Subdomains found: {len(found)}"
    )
    print(
        f"[*] DNS records found: {record_count}"
    )
    print(
        f"[*] Web services found: {http_count}"
    )

    return found


def save_results(results, output_file):
    try:
        with open(output_file, "w") as file:

            for hostname, records, http_info in results:

                file.write(
                    f"{hostname}\n"
                )

                for record_type, value in records:
                    file.write(
                        f"    {record_type} -> {value}\n"
                    )

                if http_info:
                    file.write(
                        f"    HTTP -> "
                        f"{http_info['status']} "
                        f"{http_info['url']}\n"
                    )

                    file.write(
                        f"    Title -> "
                        f"{http_info['title']}\n"
                    )

                    file.write(
                        f"    Server -> "
                        f"{http_info['server']}\n"
                    )

                else:
                    file.write(
                        "    HTTP -> "
                        "No web service detected\n"
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
            "SubTrace - Lightweight DNS and "
            "HTTP reconnaissance tool"
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
            "Number of concurrent lookups "
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