# FAPA — Fake Access Point Attack Tool

Version 0.3 · May 2025  |  Proof-of-concept framework for Wi-Fi security research and classroom demos

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-v0.3-orange.svg)

## Overview

The Fake Access Point Attack Tool (FAPA) is a full-stack lab environment that shows how dangerous it is to join "free Wi-Fi". It creates a rogue AP, silently funnels client traffic through the attacker, and then lets you chain together Man-in-the-Middle attacks, phishing portals, vulnerability scans, packet injection, credential harvesting, real-time monitoring, and reporting—all from one interactive Python script.

> **Disclaimer:** This tool is provided for research and educational purposes only. Use it exclusively on systems and networks where you have explicit, written authorisation. Unauthorised use is illegal and unethical. The developers accept no responsibility for misuse or resulting damages.

## Features

Below is a comprehensive list of what FAPA can do. Items marked 🆕 are new in v0.3.

| Category | Details |
|----------|---------|
| Fake Access Point Creation | Build an open AP with hostapd, dnsmasq, DHCP pool, and NAT. Choose guided (custom SSID/channel) or one-click automatic mode. |
| Man-in-the-Middle (MITM) Suite | Centralised MITMAttacker class orchestrates each attack and cleans up afterward.<br>• Bettercap ARP Spoofing – classic network MITM.<br>• Ettercap DNS Spoofing – GUI + caplet helper.<br>• mitmproxy – transparent HTTP/S interception.<br>• SSLStrip + 🆕 – downgrade HTTPS and capture plain-text creds.<br>• Form Grabbing 🆕 – dump HTTP/HTTPS form data & cookies to ~/creds.txt.<br>• WPAD Spoofing 🆕 – serve malicious wpad.dat, auto-starts Apache, tails hits.<br>• HSTS Bypass 🆕 – bulk /etc/hosts override with live tcpdump monitor.<br>• Evilginx v3.3.0 – transparent phishing with ready-to-compile helper.<br>• Full Traffic Capture – tcpdump to ./mitm_capture.pcap. |
| Phishing Portal | Launch Wifiphisher scenarios against the fake AP or scan for any ESSID, then harvest credentials. |
| Traffic Sniffing, Injection & Manipulation | Passive: Wireshark/tcpdump launcher. Active: Scapy wizard to capture packets, inject ICMP/TCP, edit headers, swap payloads, and resend. |
| Vulnerability Scanning | Customisable Nmap engine picker: select NSE categories, add per-category script-args, scan connected clients, view results in-terminal. |
| Client Monitoring | Real-time list built from hostapd station table + dnsmasq leases. Press Enter to refresh every 5 s. |
| Real-Time Telegram Notifications 🆕 | Background thread posts a Markdown list of connected clients every 10 s, but only when it changes. Configure bot token & chat ID once; stop via menu. |
| CSV Reporting | Write attack descriptions & results to CSV; later open and paginate records inside FAPA. |
| Network Restoration | Stop hostapd/dnsmasq/Bettercap, flush iptables/nft, reset modes, and restore backups of ettercap & hosts—all with one menu option. |
| AI Phishing | Soon AI-assisted phishing page generation |

## Screenshot

*(Screenshot placeholder)*

## Installation

### Requirements

- OS: Kali Linux (recommended) or any Debian-based distro
- Python 3.9+
- Root privileges (sudo)
- Packages (auto-installed on first run):
  ```
  aircrack-ng  apache2  bettercap  dnsmasq  git  gnome-terminal
  golang-go    hostapd  mitmproxy  tcpdump  wifiphisher
  ```
- Python libs: requests, scapy (installed inside local venv/)

### Setup

```bash
# 1 · Clone the repo
$ git clone https://github.com/LvL23HT/FAPA.git
$ cd FAPA

# 2 · Launch the script (creates venv & installs dependencies)
$ sudo python3 FAPA.py

# Or to make the script executable
$ chmod +x FAPA.py
$ sudo ./FAPA.py
```


On first start FAPA checks for root, creates venv/, fetches all system deps, displays the Code of Conduct prompt, and then shows the main menu.

## Usage

The interactive menu flow mirrors the feature list:

1. **Create Fake AP** – set up a rogue hotspot.
2. **MITM Attacks** – open sub-menu with all nine modules listed above.
3. **Phishing Portal** – run Wifiphisher campaigns.
4. **Sniffing, Injection, Manipulation** – Wireshark/tcpdump/Scapy utilities.
5. **Vulnerability Scanning** – Nmap NSE wizard.
6. **Client Monitoring** – live station list.
7. **Real-Time Notifications** – Telegram bot start/stop.
8. **Reporting** – generate or analyse CSV incident logs.
9. **Restore Network Configuration** – full cleanup.
10. **Help & Documentation** – built-in manual with links.
11. **Exit** – safely terminate; auto-restores interfaces & removes venv/.

## Code of Conduct & Disclaimer

Before the tool will run you must type `I agree` at the prompt.  
This confirms that you have authorisation, accept all legal responsibility, and will use FAPA only for ethical research.

## Contributing

We welcome pull requests from researchers, educators and red-teamers.

1. Fork → `git checkout -b feat/<topic>`
2. Follow PEP 8, include type hints & docstrings.
3. Add/update markdown docs when relevant.
4. Test exclusively in a lab environment.
5. Submit a PR with clear description, screenshots or GIF demos.

## Additional Resources

- Hostapd: https://w1.fi/hostapd/
- Dnsmasq: http://www.thekelleys.org.uk/dnsmasq/doc.html
- Bettercap: https://www.bettercap.org/
- Ettercap: https://ettercap.github.io/ettercap/
- mitmproxy: https://mitmproxy.org/
- Wifiphisher: https://wifiphisher.org/
- Evilginx2: https://github.com/kgretzky/evilginx2
- Scapy: https://scapy.readthedocs.io/
- Nmap NSE: https://nmap.org/nsedoc/
- Telegram Bot API: https://core.telegram.org/bots/api

## License

This project is licensed under the MIT License. See LICENSE for details.

FAPA is in active development. Your suggestions and bug reports help drive new features—thank you!
