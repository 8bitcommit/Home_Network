"""
LocalNetworkScan.py — Home Network Inventory Script

This script scans your local network to identify connected devices using ARP requests.
For each discovered device, it:
- Retrieves the IP and MAC address
- Looks up the device vendor using the MAC OUI
- Quietly probes a set of common TCP ports (22, 80, 443, etc.)
- Outputs results to a CSV file for later review

The goal is to provide visibility into who built the devices on your network
and what services they may be exposing — without triggering alarms or using loud scans.

Author: Adam Kearsey
Blog: https://adamkearsey.com/2025-05-12-Scan_Home_Network/
License: MIT
"""


from scapy.all import ARP, Ether, srp
    from mac_vendor_lookup import MacLookup
    import socket
    import time
    import csv

    Local_Subnet = '192.168.1.0/24'
    COMMON_PORTS = [
        21, 22, 23, 53, 80, 123, 137, 138, 139, 445,
        443, 3306, 3389, 5357, 8000, 8080, 8443
    ]
    
    def quietly_probe_ports(ip, ports):
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
                time.sleep(0.3)
            except:
                pass
        return open_ports

    def quiet_arp_scan(subnet = Local_Subnet, output_file='network_inventory.csv'):
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=0)[0]

        mac_lookup = MacLookup()
        try:
            mac_lookup.update_vendors()
        except:
            pass

        inventory = []

        for _, received in result:
            ip = received.psrc
            mac = received.hwsrc
            vendor = 'Unknown'
            try:
                vendor = mac_lookup.lookup(mac)
            except:
                pass

            open_ports = quietly_probe_ports(ip, COMMON_PORTS)
            ports_str = ', '.join(map(str, open_ports)) if open_ports else 'None'

            print(f"\nDevice Found:")
            print(f"  IP: {ip}")
            print(f"  MAC: {mac}")
            print(f"  Vendor: {vendor}")
            print(f"  Open Ports: {ports_str}")

            inventory.append({
                'IP': ip,
                'MAC': mac,
                'Vendor': vendor,
                'Open Ports': ports_str
            })

        with open(output_file, mode='w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['IP', 'MAC', 'Vendor', 'Open Ports'])
            writer.writeheader()
            writer.writerows(inventory)

        print(f"\nInventory saved to {output_file}")

    if __name__ == '__main__':
        quiet_arp_scan()
