import socket
from scapy.all import ARP, Ether, srp
import ipaddress
import subprocess
import threading

def get_device_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address

def get_network(ip_address):
    network = f"{ip_address}/24"
    return network

def scan_network(network):
    arp_request = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=2, verbose=False)[0]
    devices = []
    if result:
        for el in result[0]:
            ip_address = str(el.psrc)
            mac_address = el.hwsrc
            device_info = f"IP: {ip_address}, MAC: {mac_address}"
            devices.append(device_info)
    return devices

def scan_ports(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                return f"{ip}:{port} is open"
            elif result == 1:
                return f"{ip}:{port} is closed"
            else:
                return f"{ip}:{port} is unreachable"
    except ConnectionRefusedError:
        return f"{ip}:{port} is unreachable"

def scan_ports_async(ip, port):
    lock = Lock()
    threads = []
    def worker(ip, port):
        result = scan_ports(ip, port)
        with lock:
            print(result)
    thread = Thread(target=worker, args=(ip, port))
    threads.append(thread)
    thread.start()

def scan_devices(ip_range):
    threads = []
    for device in ip_range:
        thread = threading.Thread(target=scan_ports, args=(device, 1))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

def main():
    ip_address = get_device_ip()
    network = get_network(ip_address)
    devices = scan_network(network)
    print("Scanning ports on devices...")
    scan_devices(network)

if __name__ == "__main__":
    main()