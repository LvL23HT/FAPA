# FAPA - Fake Access Point Attack Tool

## Overview

The **Fake Access Point Attack Tool** is a proof-of-concept (PoC) designed to demonstrate the risks associated with connecting to "free Wi-Fi" access points. This tool simulates a malicious access point to lure victims and then allows you to execute various attacks such as Man-In-The-Middle (MITM), phishing, vulnerability scanning, and packet manipulation.

**Disclaimer:**  
This tool is provided **for research and educational purposes only**. Use it only in environments where you have explicit permission to perform security testing. Unauthorized use on networks without consent is illegal and unethical. By using this tool, you agree that the developers are not responsible for any damage or legal issues that may arise from its misuse.

## Features

- **Fake Access Point Creation:**  
  Create a malicious access point (Fake AP) using `hostapd`, `dnsmasq`, and NAT. This helps demonstrate how easily victims can be lured into connecting to a rogue network.

- **MITM Attacks:**  
  Perform various MITM attacks using:
  - **Bettercap** for ARP spoofing.
  - **Ettercap** for DNS spoofing (with GUI and caplets).
  - **Mitmproxy** for Proxy MITM.

- **Phishing Portal:**  
  Deploy phishing scenarios using **Wifiphisher** to capture credentials and sensitive information.

- **Traffic Sniffing, Injection, and Packet Manipulation:**  
  Capture, analyze, inject, and manipulate network packets using tools like `tcpdump` and **Scapy**.

- **Vulnerability Scanning:**  
  Scan connected devices for vulnerabilities using **Nmap** with a customizable set of NSE (Nmap Scripting Engine) script categories and arguments.

- **Client Monitoring:**  
  Monitor in real-time the devices connected to your Fake AP.

- **Real-Time Notifications:**  
  Receive notifications about connected clients via a Telegram bot.

- **Reporting:**  
  Generate and analyze reports in CSV format detailing the outcomes of attacks and scans.

- **Network Configuration Restoration:**  
  Quickly restore the network configuration to its original state after testing.

- **Future Internationalization:**  
  Planned support for multiple languages to accommodate researchers worldwide.

## Screenshot
![FAPA Tool Screenshot.](/Screenshot.png "FAPA.")

## Installation

### Requirements

- **Operating System:** Kali Linux (recommended) or any Linux distribution.
- **Python 3.x**  
- **Packages:**  
  - `aircrack-ng`, `hostapd`, `dnsmasq`, `bettercap`, `wifiphisher`, `tcpdump`, `gnome-terminal`, `scapy`, `evilginx2`
- **Privileges:** Must be run as root or with sudo.

### Setup

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/LvL23HT/FAPA.git
   cd FAPA

2. **Run the Script:**

   ```bash
   sudo python3 FAPA.py
   
When the script starts, it will check for root privileges and then display a Code of Conduct and Disclaimer that must be accepted before proceeding.

## Usage

The tool provides an interactive menu with options for:

1. **Creating a Fake AP:**
Set up a rogue access point to lure victims.

2. **MITM Attacks:**
Launch various MITM techniques using Bettercap, Ettercap, and mitmproxy.

3. **Phishing Portal:**
Execute phishing campaigns with Wifiphisher.

4. **Sniffing, Injection, and Packet Manipulation:**
Capture and interact with network traffic using Scapy and tcpdump.

5. **Vulnerability Scanning:**
Scan connected devices with Nmap using customizable NSE script categories and arguments.

6. **Client Monitoring:**
Monitor connected devices in real time.

7. **Real-Time Notifications:**
Set up Telegram notifications for client changes.

8. **Reporting:**
Generate and analyze CSV reports.

9. **Restoring Network Configuration:**
Return the network to its original state after an attack.

10. **Help & Documentation:**
Display detailed help, usage instructions, and links to official documentation.

11. **Exit:**
Safely exit the tool

## Code of Conduct & Disclaimer
> Before proceeding, you must accept the following conditions:
Code of Conduct & Disclaimer
This tool is provided solely for research and educational purposes.
You agree to use this tool responsibly and only in authorized environments.
Unauthorized use is illegal and may result in severe legal consequences.
The developers are not responsible for any damage or legal issues resulting from misuse.

>>Type "I agree" to continue.

## Contributing
Contributions are welcome! We invite researchers and security professionals to help improve this tool. Please fork the repository and submit pull requests with your enhancements. For major changes, please open an issue first to discuss what you would like to change.

## Additional Resources
- **Hostapd:** https://w1.fi/hostapd/

- **Dnsmasq:** http://www.thekelleys.org.uk/dnsmasq/doc.html

- **Bettercap:** https://www.bettercap.org/

- **Ettercap:** https://ettercap.github.io/ettercap/

- **Mitmproxy:** https://mitmproxy.org/

- **Wifiphisher:** https://wifiphisher.org/

- **Scapy:** https://scapy.readthedocs.io/en/latest/usage.html

- **Nmap NSE Documentation:** https://nmap.org/nsedoc/

- **Telegram Bot API:** https://core.telegram.org/bots/api

## License
This project is licensed under the MIT License. See the [LICENSE](https://choosealicense.com/licenses/mit/) file for details.

##
Note: This tool is a work in progress. We welcome contributions from the research community to improve functionality, add language support, and refine features.
