# SubTrace 🔎

A lightweight Python tool for discovering subdomains through DNS resolution.

## Features

* 🔎 Subdomain discovery using a custom wordlist
* 🌐 DNS resolution
* 📍 Displays resolved IP addresses
* 📋 External wordlist support
* ⚡ Lightweight and fast
* 🐍 Built with Python's standard library

## Requirements

* Python 3.x
* Git

No external Python packages are required.

## Installation

Clone the repository:

```bash
git clone https://github.com/ankitrasaily00-hash/SubTrace.git
cd SubTrace
```

## Usage

Run SubTrace with a domain:

```bash
python subtrace.py example.com
```

You can also provide a URL:

```bash
python subtrace.py https://example.com
```

### Example

```text
  _____       _ _____
 / ____|     | |_   _|
| (___  _   _| | | |
 \___ \| | | | | | |
 ____) | |_| | | | |
|_____/ \__,_|_| |_|

      SubTrace
  Subdomain Discovery Tool

[*] Target: example.com
[*] Wordlist: 22 entries

[+] www.example.com       -> 93.184.216.34
[+] mail.example.com      -> 93.184.216.35

[*] Scan complete
[*] Found: 2
```

## Project Structure

```text
SubTrace/
├── .gitignore
├── README.md
├── requirements.txt
├── subdomains.txt
└── subtrace.py
```

## How It Works

SubTrace takes a target domain and combines it with entries from `subdomains.txt`.

For example:

```text
www
mail
api
dev
```

becomes:

```text
www.example.com
mail.example.com
api.example.com
dev.example.com
```

The tool then performs DNS resolution for each hostname and reports hosts that successfully resolve.

## Wordlist

You can customize `subdomains.txt` by adding additional subdomain prefixes:

```text
www
mail
api
dev
staging
portal
dashboard
```

One entry should be placed on each line.

## Legal & Ethical Use

SubTrace is intended for educational purposes, security research, and authorized reconnaissance.

Only scan domains that you own or have explicit permission to assess.

The author is not responsible for misuse of this tool.

## License

This project is released under the MIT License.
