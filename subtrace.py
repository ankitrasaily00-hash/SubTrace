import argparse
import csv
import json
import time
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
        with open(wordlist, "r", encoding="utf-8") as file:
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
    if not text:
        return "N/A"

    lower_text = text.lower()

    start = lower_text.find("<title>")

    if start == -1:
        return "N/A"

    end = lower_text.find(
        "</title>",
        start
    )

    if end == -1:
        return "N/A"

    title = text[start + 7:end].strip()

    return title if title else "N/A"


def check_http(hostname):
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
                    "User-Agent": "SubTrace/8.0"
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
    web_count = 0
    status_2xx = 0
    status_3xx = 0
    status_4xx_5xx = 0

    if not subdomains:
        return found

    print(f"[*] Target: {domain}")
    print(f"[*] Wordlist: {len(subdomains)} entries")
    print(f"[*] Workers: {workers}")
    print(
        f"[*] DNS Records: "
        f"{', '.join(RECORD_TYPES)}"
    )
    print("[*] HTTP Detection: HTTPS + HTTP")
    print("[*] Timeout: 5 seconds\n")

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

            print(
                " " * 60,
                end="\r"
            )

            print(f"[+] {hostname}")

            for record in records:
                record_count += 1

                print(
                    f"    {record['type']:<6} "
                    f"-> {record['value']}"
                )

            if http_info:
                web_count += 1

                status = http_info["status"]

                if 200 <= status < 300:
                    status_2xx += 1

                elif 300 <= status < 400:
                    status_3xx += 1

                elif status >= 400:
                    status_4xx_5xx += 1

                print(
                    f"    HTTP   -> "
                    f"{status} "
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

    print("\n[*] Scan complete")
    print(
        f"    Subdomains  : {len(found)}"
    )
    print(
        f"    DNS records : {record_count}"
    )
    print(
        f"    Web services: {web_count}"
    )
    print(
        f"    HTTP 2xx    : {status_2xx}"
    )
    print(
        f"    HTTP 3xx    : {status_3xx}"
    )
    print(
        f"    HTTP 4xx/5xx: {status_4xx_5xx}"
    )

    return found


def save_text(results, output_file):
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

                for record in result["dns_records"]:
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
                    http_status = http_info["status"]
                    url = http_info["url"]
                    title = http_info["title"]
                    server = http_info["server"]
                    response_time = (
                        http_info["response_time"]
                    )
                else:
                    http_status = ""
                    url = ""
                    title = ""
                    server = ""
                    response_time = ""

                for record in result["dns_records"]:

                    writer.writerow(
                        [
                            result["hostname"],
                            record["type"],
                            record["value"],
                            http_status,
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
        save_text(
            results,
            args.output
        )

    if args.json and results:
        save_json(
            results,
            args.json
        )

    if args.csv and results:
        save_csv(
            results,
            args.csv
        )


if __name__ == "__main__":
    main()