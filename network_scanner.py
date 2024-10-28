# network_scanner.py
# sources:
# https://dev.to/dharmil18/writing-a-network-scanner-using-python-3b80
# https://medium.com/@wizD/a-simple-port-scanner-using-python-e541454ea570

import argparse
import scapy.all as scapy
import socket

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP address/addresses')
    parser.add_argument('-p', '--ports', dest='ports', help='Comma-separated list and/or ranges (e.g., 22, 80, 443 or 1-65535 or 22, 80, 100-443)')
    options = parser.parse_args()
    
    # Check for errors (i.e., if the user does not specify the target IP address)
    if not options.target:
        parser.error("[-] Please specify an IP address or addresses; use --help for more info.")
    return options

def parse_ports(port_input):
    ports = []
    for item in port_input.split(','):
        if '-' in item:
            start_str, end_str = item.split('-')
            start = int(start_str)
            end = int(end_str)
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(item))
    return ports
            

def scan_network(ip):
    # Create an ARP Request frame
    #   hwsrc   =   source MAC address
    #   psrc    =   source IP address
    #   hwdst   =   destination MAC address
    #   pdst    =   destination IP address
    arp_request = scapy.ARP(pdst=ip)
    # print(arp_request.show())
    
    # Create an Ethernet frame with destination address (dst) set to
    # ff:ff:ff:ff:ff:ff, which is a broadcast MAC address
    broadcast_ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the ARP Request and Ethernet frame
    arp_request_broadcast = broadcast_ether / arp_request
    # print(arp_request_broadcast.show())
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    active_hosts = []
    for response in answered_list:
        active_hosts.append({'ip': response[1].psrc, 'mac': response[1].hwsrc})

    return active_hosts

def pretty_print_result(active_hosts, ports):
    print("--------------------------------------------------------------")
    print("IP Address\t\tMAC Address\t\tOpen Ports")
    print("--------------------------------------------------------------")
    
    # Iterating through each dictionary in the list and printing values
    for host in active_hosts:
        open_ports = scan_ports(host['ip'], ports)
        if open_ports:
            ports_str = ', '.join(str(port) for port in open_ports)
        else:
            ports_str = "No open ports"
        print(f"{host['ip']}\t\t{host['mac']}\t{ports_str}")
        
def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        try:
            # sock: network connection endpoint
            #   socket.AF_INET: specifies the address family (IPv4) to use
            #   socket.SOCK_STREAM: specifies that this is a stream-based (TCP) connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set timeout of 1 second on the socket
            sock.settimeout(1)
            # Attempts connection. Returns 0 if the connection was successful
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception as e:
            print(f"Error scanning port {port} on {ip}: {e}")
    return open_ports
        
def main(): 
    options = get_args()
    if options.ports:
        ports_to_scan = parse_ports(options.ports)
    else:
        ports_to_scan = [22, 80, 443]
    scanned_output = scan_network(options.target)
    pretty_print_result(scanned_output, ports_to_scan)
    
if __name__ == "__main__":
    main()