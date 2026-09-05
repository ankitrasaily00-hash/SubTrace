import argparse
import dns.resolver
import dns.exception


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


def resolve_dns(hostname):
    records = []

    try:
        answers = dns.resolver.resolve(hostname, "A")

        for answer in answers:
            records.append(
                ("A", str(answer))
            )

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
            records.append(
                ("CNAME", str(answer))
            )

    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        pass

    return records


def find_subdomains(domain, wordlist):
    subdomains = load_subdomains(wordlist)
    found = []

    print(f"[*] Target: {domain}")
    print(f"[*] Wordlist: {len(subdomains)} entries\n")

    for subdomain in subdomains:
        hostname = f"{subdomain}.{domain}"

        records = resolve_dns(hostname)

        if records:
            found.append((hostname, records))

            for record_type, value in records:
                print(
                    f"[+] {hostname:<35} "
                    f"{record_type:<6} -> {value}"
                )

    print("\n[*] Scan complete")
    print(f"[*] Found: {len(found)}")

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
        save_results(
            results,
            args.output
        )


if __name__ == "__main__":
    main()