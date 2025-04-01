from scapy.all import *
import netifaces

def list_interfaces():
    print("\nAvailable Network Interfaces (from netifaces):")
    print("-" * 50)
    
    # Get all interfaces using netifaces
    interfaces = netifaces.interfaces()
    
    for interface in interfaces:
        try:
            # Get interface details
            addrs = netifaces.ifaddresses(interface)
            
            # Get IPv4 address if available
            ipv4 = addrs.get(netifaces.AF_INET, [{'addr': 'No IPv4'}])[0]['addr']
            
            print(f"Interface: {interface}")
            print(f"IPv4 Address: {ipv4}")
            print("-" * 50)
            
        except Exception as e:
            print(f"Error getting details for {interface}: {str(e)}")
            print("-" * 50)

    print("\nAvailable Network Interfaces (from Scapy):")
    print("-" * 50)
    
    # Get interfaces using Scapy
    scapy_interfaces = get_if_list()
    for iface in scapy_interfaces:
        try:
            print(f"Interface: {iface}")
            if iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                ipv4 = addrs.get(netifaces.AF_INET, [{'addr': 'No IPv4'}])[0]['addr']
                print(f"IPv4 Address: {ipv4}")
            print("-" * 50)
        except Exception as e:
            print(f"Error getting details for {iface}: {str(e)}")
            print("-" * 50)

if __name__ == "__main__":
    print("Network Interface List")
    print("=" * 50)
    list_interfaces() 