import argparse
import csv
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.reversename
import dns.resolver
import requests


# ============================================================
# SUBTRACE CONFIGURATION
# ============================================================

VERSION = "12.0.1"

WORDLIST = "subdomains.txt"
DEFAULT_WORKERS = 10
REQUEST_TIMEOUT = 5

RECORD_TYPES = [
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "SOA",
    "SRV",
]


# ============================================================
# BANNER
# ============================================================

BANNER = r"""
 ███████╗██╗   ██╗██████╗ ████████╗██████╗  █████╗  ██████╗███████╗
 ██╔════╝██║   ██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
 ███████╗██║   ██║██████╔╝   ██║   ██████╔╝███████║██║     █████╗
 ╚════██║██║   ██║██╔══██╗   ██║   ██╔══██╗██╔══██║██║     ██╔══╝
 ███████║╚██████╔╝██████╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗
 ╚══════╝ ╚═════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝

                  DNS + HTTP RECONNAISSANCE
              ─────────────────────────────────
                         v12.0.1
"""


# ============================================================
# WORDLIST
# ============================================================

def load_subdomains(wordlist):
    """Load unique subdomain prefixes from a wordlist."""

    try:
        with open(wordlist, "r", encoding="utf-8") as file:
            subdomains = []

            for line in file:
                value = line.strip()

                if not value:
                    continue

                if value.startswith("#"):
                    continue

                subdomains.append(value)

            return list(dict.fromkeys(subdomains))

    except FileNotFoundError:
        print(f"[-] Wordlist not found: {wordlist}")
        return []


# ============================================================
# DNS RESOLUTION
# ============================================================

def resolve_record(hostname, record_type):
    """Resolve one DNS record type."""

    records = []

    try:
        answers = dns.resolver.resolve(
            hostname,
            record_type,
        )

        for answer in answers:
            records.append(
                {
                    "type": record_type,
                    "value": str(answer),
                }
            )

    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        pass

    except Exception:
        pass

    return records


def resolve_ptr(ip_address):
    """Perform reverse DNS lookup for an IP address."""

    records = []

    try:
        reverse_name = dns.reversename.from_address(ip_address)

        answers = dns.resolver.resolve(
            reverse_name,
            "PTR",
        )

        for answer in answers:
            records.append(
                {
                    "type": "PTR",
                    "value": str(answer),
                    "source": ip_address,
                }
            )

    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        pass

    except Exception:
        pass

    return records


def resolve_dns(hostname):
    """Resolve all configured DNS record types."""

    records = []

    for record_type in RECORD_TYPES:
        records.extend(
            resolve_record(
                hostname,
                record_type,
            )
        )

    # Reverse DNS for discovered IP addresses.
    ip_addresses = [
        record["value"]
        for record in records
        if record["type"] in ("A", "AAAA")
    ]

    for ip_address in sorted(set(ip_addresses)):
        records.extend(
            resolve_ptr(ip_address)
        )

    return hostname, records


# ============================================================
# WILDCARD DNS DETECTION
# ============================================================

def resolve_a_records(hostname):
    """Resolve A records for wildcard DNS detection."""

    records = []

    try:
        answers = dns.resolver.resolve(
            hostname,
            "A",
        )

        for answer in answers:
            records.append(str(answer))

    except Exception:
        pass

    return sorted(set(records))


def generate_random_hostname(domain):
    """Generate a random hostname for wildcard testing."""

    timestamp = str(time.time_ns())

    suffix = re.sub(
        r"[^a-z0-9]",
        "",
        timestamp.lower(),
    )

    return f"subtrace-{suffix}.{domain}"


def detect_wildcard_dns(domain):
    """
    Detect basic wildcard A-record behavior.

    Random hostnames are queried several times.
    If they resolve to addresses, those addresses
    are treated as possible wildcard DNS.
    """

    wildcard_addresses = []

    for _ in range(3):
        hostname = generate_random_hostname(domain)

        addresses = resolve_a_records(hostname)

        if addresses:
            wildcard_addresses.extend(addresses)

    return sorted(set(wildcard_addresses))


def is_wildcard_match(records, wildcard_addresses):
    """Check whether an A-record response matches wildcard DNS."""

    if not wildcard_addresses:
        return False

    a_records = sorted(
        {
            record["value"]
            for record in records
            if record["type"] == "A"
        }
    )

    if not a_records:
        return False

    return a_records == sorted(
        set(wildcard_addresses)
    )


# ============================================================
# HTTP DETECTION
# ============================================================

def extract_title(text):
    """Extract and clean the HTML page title."""

    if not text:
        return "N/A"

    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        text,
        re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return "N/A"

    title = re.sub(
        r"\s+",
        " ",
        match.group(1),
    ).strip()

    return title if title else "N/A"


def check_http(hostname):
    """Check HTTPS first, then HTTP."""

    urls = [
        f"https://{hostname}",
        f"http://{hostname}",
    ]

    for url in urls:
        start_time = time.perf_counter()

        try:
            response = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={
                    "User-Agent": f"SubTrace/{VERSION}",
                },
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
                    "Unknown",
                ),
                "response_time": round(
                    response_time,
                    3,
                ),
            }

        except requests.RequestException:
            continue

    return None


# ============================================================
# SUBDOMAIN SCANNING
# ============================================================

def scan_subdomain(
    domain,
    subdomain,
    wildcard_addresses,
):
    """Resolve DNS and check HTTP for one subdomain."""

    hostname = f"{subdomain}.{domain}"

    try:
        hostname, records = resolve_dns(hostname)

        if not records:
            return {
                "hostname": hostname,
                "dns_records": [],
                "http": None,
                "wildcard": False,
            }

        wildcard = is_wildcard_match(
            records,
            wildcard_addresses,
        )

        http_info = check_http(hostname)

        return {
            "hostname": hostname,
            "dns_records": records,
            "http": http_info,
            "wildcard": wildcard,
        }

    except Exception:
        return {
            "hostname": hostname,
            "dns_records": [],
            "http": None,
            "wildcard": False,
        }


def print_result(result):
    """Print one discovered subdomain."""

    hostname = result["hostname"]
    records = result["dns_records"]
    http_info = result["http"]
    wildcard = result["wildcard"]

    print(f"\n[+] {hostname}")

    if wildcard:
        print(
            "    DNS    -> Possible wildcard match"
        )

    for record in records:
        record_type = record["type"]
        record_value = record["value"]

        print(
            f"    {record_type:<6} -> {record_value}"
        )

        if record_type == "PTR":
            source = record.get(
                "source",
                "Unknown",
            )

            print(
                f"             Reverse of -> {source}"
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


# ============================================================
# SCAN ENGINE
# ============================================================

def find_subdomains(
    domain,
    wordlist,
    workers,
    quiet=False,
):
    """Scan subdomains concurrently."""

    subdomains = load_subdomains(wordlist)

    found = []

    record_count = 0
    web_count = 0
    status_2xx = 0
    status_3xx = 0
    status_4xx_5xx = 0
    wildcard_count = 0

    if not subdomains:
        return {
            "results": [],
            "record_count": 0,
            "web_count": 0,
            "status_2xx": 0,
            "status_3xx": 0,
            "status_4xx_5xx": 0,
            "wildcard_count": 0,
            "wildcard_addresses": [],
        }

    wildcard_addresses = detect_wildcard_dns(domain)

    if not quiet:
        print(f"[*] Target: {domain}")

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
            "[*] Reverse DNS: "
            "PTR for A/AAAA"
        )

        print(
            "[*] HTTP Detection: "
            "HTTPS + HTTP"
        )

        print(
            f"[*] Timeout: "
            f"{REQUEST_TIMEOUT} seconds"
        )

        if wildcard_addresses:
            print(
                "[*] Wildcard DNS: "
                f"Detected "
                f"({', '.join(wildcard_addresses)})"
            )
        else:
            print(
                "[*] Wildcard DNS: "
                "Not detected"
            )

        print()

    completed = 0
    total = len(subdomains)

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        tasks = [
            executor.submit(
                scan_subdomain,
                domain,
                subdomain,
                wildcard_addresses,
            )
            for subdomain in subdomains
        ]

        for task in as_completed(tasks):
            completed += 1

            try:
                result = task.result()

            except Exception:
                continue

            if not quiet:
                print(
                    f"[*] Progress: "
                    f"{completed}/{total}",
                    end="\r",
                )

            if not result["dns_records"]:
                continue

            found.append(result)

            record_count += len(
                result["dns_records"]
            )

            if result["wildcard"]:
                wildcard_count += 1

            http_info = result["http"]

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
                    " " * 70,
                    end="\r",
                )

                print_result(result)

    found.sort(
        key=lambda item: item["hostname"]
    )

    return {
        "results": found,
        "record_count": record_count,
        "web_count": web_count,
        "status_2xx": status_2xx,
        "status_3xx": status_3xx,
        "status_4xx_5xx": status_4xx_5xx,
        "wildcard_count": wildcard_count,
        "wildcard_addresses": wildcard_addresses,
    }


# ============================================================
# TEXT OUTPUT
# ============================================================

def save_text(results, output_file):
    """Save results in human-readable TXT format."""

    try:
        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as file:

            for result in results:
                file.write(
                    f"{result['hostname']}\n"
                )

                if result["wildcard"]:
                    file.write(
                        "    DNS -> "
                        "Possible wildcard match\n"
                    )

                for record in result["dns_records"]:
                    file.write(
                        f"    {record['type']} "
                        f"-> {record['value']}\n"
                    )

                    if record["type"] == "PTR":
                        source = record.get(
                            "source",
                            "Unknown",
                        )

                        file.write(
                            "        "
                            f"Reverse of -> {source}\n"
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


# ============================================================
# JSON OUTPUT
# ============================================================

def save_json(results, output_file):
    """Save results as JSON."""

    try:
        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                results,
                file,
                indent=4,
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


# ============================================================
# CSV OUTPUT
# ============================================================

def save_csv(results, output_file):
    """Save results as CSV."""

    try:
        with open(
            output_file,
            "w",
            newline="",
            encoding="utf-8",
        ) as file:

            writer = csv.writer(file)

            writer.writerow(
                [
                    "Hostname",
                    "Wildcard",
                    "Record Type",
                    "Record Value",
                    "PTR Source",
                    "HTTP Status",
                    "URL",
                    "Title",
                    "Server",
                    "Response Time",
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

                for record in result["dns_records"]:
                    writer.writerow(
                        [
                            result["hostname"],
                            result["wildcard"],
                            record["type"],
                            record["value"],
                            record.get(
                                "source",
                                "",
                            ),
                            status,
                            url,
                            title,
                            server,
                            response_time,
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


# ============================================================
# SUMMARY
# ============================================================

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

    print(
        f"    Wildcard    : "
        f"{scan_data['wildcard_count']}"
    )


# ============================================================
# DOMAIN CLEANING
# ============================================================

def clean_domain(domain):
    """Clean HTTP/HTTPS prefixes and paths."""

    domain = domain.strip()

    domain = re.sub(
        r"^https?://",
        "",
        domain,
        flags=re.IGNORECASE,
    )

    domain = domain.split("/")[0]

    domain = domain.rstrip(".")

    return domain.lower()


# ============================================================
# CLI
# ============================================================

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
        help="Target domain",
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        default=WORDLIST,
        help=(
            f"Subdomain wordlist "
            f"(default: {WORDLIST})"
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        help=(
            "Save human-readable results "
            "to a file"
        ),
    )

    parser.add_argument(
        "--json",
        help="Save results as JSON",
    )

    parser.add_argument(
        "--csv",
        help="Save results as CSV",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=DEFAULT_WORKERS,
        help=(
            "Number of concurrent lookups "
            f"(default: {DEFAULT_WORKERS})"
        ),
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Show only the final summary",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"SubTrace {VERSION}",
    )

    args = parser.parse_args()

    if args.threads < 1:
        parser.error(
            "threads must be at least 1"
        )

    domain = clean_domain(args.domain)

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
        args.quiet,
    )

    print_summary(scan_data)

    if args.output:
        save_text(
            scan_data["results"],
            args.output,
        )

    if args.json:
        save_json(
            scan_data["results"],
            args.json,
        )

    if args.csv:
        save_csv(
            scan_data["results"],
            args.csv,
        )

    if not scan_data["results"]:
        return 1

    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    sys.exit(main())