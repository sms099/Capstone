import os
import socket
import scapy.all as scapy
import paramiko
import json
import time
import ipaddress
import requests

COMMON_PORTS = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Email Sending)",
    53: "DNS (Domain Name System)",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP (Trivial File Transfer)",
    80: "HTTP (Web Traffic)",
    110: "POP3 (Email Receiving)",
    119: "NNTP (Usenet)",
    123: "NTP (Time Protocol)",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP (Email Access)",
    161: "SNMP (Monitoring)",
    162: "SNMP Trap",
    179: "BGP (Border Gateway Protocol)",
    443: "HTTPS (Secure Web Traffic)",
    465: "SMTP over SSL",
    514: "Syslog",
    587: "SMTP Submission",
    993: "IMAP over SSL",
    995: "POP3 over SSL",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    1723: "PPTP VPN",
    1883: "MQTT (IoT)",
    2049: "NFS",
    3306: "MySQL",
    3389: "Remote Desktop (RDP)",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "Alternate HTTP",
    8443: "Alternate HTTPS",
}

OUI_LOOKUP_URL = "https://api.macvendors.com/"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "Unknown"

def get_network_range(local_ip):
    try:
        network = ipaddress.IPv4Network(local_ip + '/24', strict=False)
        return str(network)
    except Exception:
        return "10.10.17.1/24"

def is_port_open(ip, port, timeout=3):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def validate_ssh_banner(ip, port=22, timeout=3):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            if "SSH-" in banner:
                return True
    except Exception:
        pass
    return False

def get_mac_vendor(mac):
    try:
        response = requests.get(OUI_LOOKUP_URL + mac, timeout=5)
        if response.status_code == 200:
            return response.text.strip()
    except requests.RequestException:
        pass
    return "Unknown Vendor"

def scan_network(ip_range):
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
        
        devices = []
        for sent, received in answered_list:
            vendor = get_mac_vendor(received.hwsrc)
            devices.append({"ip": received.psrc, "mac": received.hwsrc, "vendor": vendor})
        return devices
    except Exception:
        return []

def scan_ports(ip):
    open_ports = {}
    for port, description in COMMON_PORTS.items():
        if is_port_open(ip, port):
            open_ports[port] = description
    return open_ports

def save_results(data, filename="results.json"):
    try:
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
        print(f"Results saved to {filename}")
    except Exception:
        pass

def main():
    local_ip = get_local_ip()
    print(f"Local IP Address: {local_ip}")
    
    network_range = get_network_range(local_ip)
    print("Scanning network...")
    devices = scan_network(network_range)
    
    if not devices:
        print("No devices found.")
        return
    
    results = []
    for device in devices:
        open_ports = scan_ports(device["ip"])
        results.append({
            "ip": device["ip"],
            "mac": device["mac"],
            "vendor": device["vendor"],
            "open_ports": open_ports
        })
    
    save_results(results)

if __name__ == "__main__":
    main() 
