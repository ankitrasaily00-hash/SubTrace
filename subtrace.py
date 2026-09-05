import argparse
import csv
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver
import requests


VERSION = "9.0.0"

WORDLIST = "subdomains.txt"
DEFAULT_WORKERS = 10
REQUEST_TIMEOUT = 5

RECORD_TYPES = [
    "A",
    "CNAME",
    "MX",
    "NS",
    "TXT",
]


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
    """Load subdomain prefixes from the wordlist."""

    try:
        with open(
            wordlist,
            "r",
            encoding="utf-8"
        ) as file:
            return [
                line.strip()
                for line in file
                if line.strip()
                and not line.strip().startswith("#")
            ]

    except FileNotFoundError:
        print(
            f"[-] Wordlist not found: {wordlist}"
        )
        return []


def resolve_record(hostname, record_type):
    """Resolve one DNS record type."""

    records = []

    try:
        answers = dns.resolver.resolve(
            hostname,
            record_type
        )

        for answer in answers:
            records.append(
                {
                    "type": record_type,
                    "value": str(answer)
                }
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
    """Resolve all configured DNS record types."""

    records = []

    for record_type in RECORD_TYPES:
        records.extend(
            resolve_record(
                hostname,
                record_type
            )
        )

    return hostname, records


def extract_title(text):
    """Extract and clean the HTML page title."""

    if not text:
        return "N/A"

    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        text,
        re.IGNORECASE | re.DOTALL
    )

    if not match:
        return "N/A"

    title = re.sub(
        r"\s+",
        " ",
        match.group(1)
    ).strip()

    return title if title else "N/A"


def check_http(hostname):
    """Check HTTPS first, then HTTP."""

    urls = [
        f"https://{hostname}",
        f"http://{hostname}"
    ]

    for url in urls:
        start_time = time.perf_counter()

        try:
            response = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={
                    "User-Agent": (
                        f"SubTrace/{VERSION}"
                    )
                }
            )

            response_time = (
                time.perf_counter() - start_time
            )

            return {
                "url": response.url,
                "status": response.status_code,
                "title": extract_title(
                    response.text
                ),
                "server": response.headers.get(
                    "Server",
                    "Unknown"
                ),
                "response_time": round(
                    response_time,
                    3
                )
            }

        except requests.RequestException:
            continue

    return None


def scan_subdomain(domain, subdomain):
    """Resolve DNS and check HTTP for one subdomain."""

    hostname = f"{subdomain}.{domain}"

    try:
        hostname, records = resolve_dns(
            hostname
        )

        if not records:
            return hostname, [], None

        http_info = check_http(
            hostname
        )

        return hostname, records, http_info

    except Exception:
        return hostname, [], None


def print_result(
    hostname,
    records,
    http_info
):
    """Print one discovered subdomain."""

    print(f"\n[+] {hostname}")

    for record in records:
        print(
            f"    {record['type']:<6} "
            f"-> {record['value']}"
        )

    if http_info:
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

        print(
            f"    Time   -> "
            f"{http_info['response_time']}s"
        )

    else:
        print(
            "    HTTP   -> "
            "No web service detected"
        )


def find_subdomains(
    domain,
    wordlist,
    workers,
    quiet=False
):
    """Scan subdomains using concurrent workers."""

    subdomains = load_subdomains(
        wordlist
    )

    found = []

    record_count = 0
    web_count = 0

    status_2xx = 0
    status_3xx = 0
    status_4xx_5xx = 0

    if not subdomains:
        return {
            "results": [],
            "record_count": 0,
            "web_count": 0,
            "status_2xx": 0,
            "status_3xx": 0,
            "status_4xx_5xx": 0
        }

    if not quiet:
        print(
            f"[*] Target: {domain}"
        )

        print(
            f"[*] Wordlist: "
            f"{len(subdomains)} entries"
        )

        print(
            f"[*] Workers: {workers}"
        )

        print(
            f"[*] DNS Records: "
            f"{', '.join(RECORD_TYPES)}"
        )

        print(
            "[*] HTTP Detection: "
            "HTTPS + HTTP"
        )

        print(
            f"[*] Timeout: "
            f"{REQUEST_TIMEOUT} seconds\n"
        )

    completed = 0
    total = len(subdomains)

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
            completed += 1

            hostname, records, http_info = (
                task.result()
            )

            if not quiet:
                print(
                    f"[*] Progress: "
                    f"{completed}/{total}",
                    end="\r"
                )

            if not records:
                continue

            result = {
                "hostname": hostname,
                "dns_records": records,
                "http": http_info
            }

            found.append(result)

            record_count += len(records)

            if http_info:
                web_count += 1

                status = http_info["status"]

                if 200 <= status < 300:
                    status_2xx += 1

                elif 300 <= status < 400:
                    status_3xx += 1

                elif status >= 400:
                    status_4xx_5xx += 1

            if not quiet:
                print(
                    " " * 60,
                    end="\r"
                )

                print_result(
                    hostname,
                    records,
                    http_info
                )

    return {
        "results": found,
        "record_count": record_count,
        "web_count": web_count,
        "status_2xx": status_2xx,
        "status_3xx": status_3xx,
        "status_4xx_5xx": status_4xx_5xx
    }


def save_text(results, output_file):
    """Save results in human-readable TXT format."""

    try:
        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:

            for result in results:

                file.write(
                    f"{result['hostname']}\n"
                )

                for record in result[
                    "dns_records"
                ]:
                    file.write(
                        f"    {record['type']} "
                        f"-> {record['value']}\n"
                    )

                http_info = result["http"]

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

                    file.write(
                        f"    Time -> "
                        f"{http_info['response_time']}s\n"
                    )

                else:
                    file.write(
                        "    HTTP -> "
                        "No web service detected\n"
                    )

                file.write("\n")

        print(
            f"[*] Text results saved to: "
            f"{output_file}"
        )

    except OSError as error:
        print(
            f"[-] Could not save results: "
            f"{error}"
        )


def save_json(results, output_file):
    """Save results as JSON."""

    try:
        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                results,
                file,
                indent=4
            )

        print(
            f"[*] JSON results saved to: "
            f"{output_file}"
        )

    except OSError as error:
        print(
            f"[-] Could not save JSON: "
            f"{error}"
        )


def save_csv(results, output_file):
    """Save results as CSV."""

    try:
        with open(
            output_file,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow(
                [
                    "Hostname",
                    "Record Type",
                    "Record Value",
                    "HTTP Status",
                    "URL",
                    "Title",
                    "Server",
                    "Response Time"
                ]
            )

            for result in results:

                http_info = result["http"]

                if http_info:
                    status = http_info["status"]
                    url = http_info["url"]
                    title = http_info["title"]
                    server = http_info["server"]
                    response_time = (
                        http_info["response_time"]
                    )

                else:
                    status = ""
                    url = ""
                    title = ""
                    server = ""
                    response_time = ""

                for record in result[
                    "dns_records"
                ]:
                    writer.writerow(
                        [
                            result["hostname"],
                            record["type"],
                            record["value"],
                            status,
                            url,
                            title,
                            server,
                            response_time
                        ]
                    )

        print(
            f"[*] CSV results saved to: "
            f"{output_file}"
        )

    except OSError as error:
        print(
            f"[-] Could not save CSV: "
            f"{error}"
        )


def print_summary(scan_data):
    """Print final scan statistics."""

    print("\n[*] Scan complete")

    print(
        f"    Subdomains  : "
        f"{len(scan_data['results'])}"
    )

    print(
        f"    DNS records : "
        f"{scan_data['record_count']}"
    )

    print(
        f"    Web services: "
        f"{scan_data['web_count']}"
    )

    print(
        f"    HTTP 2xx    : "
        f"{scan_data['status_2xx']}"
    )

    print(
        f"    HTTP 3xx    : "
        f"{scan_data['status_3xx']}"
    )

    print(
        f"    HTTP 4xx/5xx: "
        f"{scan_data['status_4xx_5xx']}"
    )


def clean_domain(domain):
    """Clean HTTP/HTTPS prefixes and trailing paths."""

    domain = domain.strip()

    domain = re.sub(
        r"^https?://",
        "",
        domain,
        flags=re.IGNORECASE
    )

    domain = domain.split("/")[0]

    domain = domain.rstrip(".")

    return domain


def main():
    """Main command-line interface."""

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
        help=(
            "Save human-readable results "
            "to a file"
        )
    )

    parser.add_argument(
        "--json",
        help="Save results as JSON"
    )

    parser.add_argument(
        "--csv",
        help="Save results as CSV"
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

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Show only the final summary"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"SubTrace {VERSION}"
    )

    args = parser.parse_args()

    if args.threads < 1:
        parser.error(
            "threads must be at least 1"
        )

    domain = clean_domain(
        args.domain
    )

    if not domain:
        parser.error(
            "a valid domain is required"
        )

    if not args.quiet:
        print(BANNER)

        print(
            f"[*] SubTrace version: "
            f"{VERSION}\n"
        )

    scan_data = find_subdomains(
        domain,
        args.wordlist,
        args.threads,
        args.quiet
    )

    # Always show the final summary.
    # Quiet mode hides detailed results only.
    print_summary(scan_data)

    if args.output and scan_data["results"]:
        save_text(
            scan_data["results"],
            args.output
        )

    if args.json and scan_data["results"]:
        save_json(
            scan_data["results"],
            args.json
        )

    if args.csv and scan_data["results"]:
        save_csv(
            scan_data["results"],
            args.csv
        )

    if not scan_data["results"]:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())