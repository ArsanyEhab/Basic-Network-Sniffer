import sys
from scapy.all import *
import logging
from datetime import datetime
import netifaces

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_interface_name(interface):
    """Convert interface name to proper format for Windows"""
    if sys.platform == 'win32':
        # If it's already in the correct format, return as is
        if interface.startswith(r'\Device\NPF_'):
            return interface
        # If it's a GUID, convert to proper format
        if interface.startswith('{'):
            return r'\Device\NPF_' + interface
        # If it's a simple name, try to find the corresponding interface
        interfaces = get_if_list()
        for iface in interfaces:
            if interface in iface:
                return iface
    return interface

# Function to handle each packet
def handle_packet(packet, log):
    try:
        # Check if the packet contains IP layer
        if not packet.haslayer(IP):
            return

        # Extract basic packet information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        length = len(packet)
        ttl = packet[IP].ttl

        # Initialize packet info string
        packet_info = f"Packet from {src_ip} to {dst_ip} | Protocol: {protocol} | Length: {length} bytes | TTL: {ttl}"

        # Add TCP-specific information if present
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            seq = packet[TCP].seq
            ack = packet[TCP].ack
            packet_info += f"\nTCP Details: {src_port} -> {dst_port} | Flags: {flags} | Seq: {seq} | Ack: {ack}"

        # Add timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packet_info = f"[{timestamp}] {packet_info}\n"

        # Write to log file
        log.write(packet_info)
        logging.info(f"Captured packet: {src_ip} -> {dst_ip}")

    except Exception as e:
        logging.error(f"Error processing packet: {str(e)}")

# Main function to start packet sniffing
def main(interface, verbose=False):
    # Create log file name with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile_name = f"sniffer_{interface}_{timestamp}.txt"
    
    try:
        # Convert interface name to proper format
        interface = get_interface_name(interface)
        logging.info(f"Using interface: {interface}")

        # Get list of available interfaces
        available_interfaces = get_if_list()
        logging.info("Available interfaces:")
        for iface in available_interfaces:
            logging.info(f"  - {iface}")

        if interface not in available_interfaces:
            logging.error(f"Interface {interface} not found in available interfaces")
            sys.exit(1)

        logging.info(f"Starting packet capture on interface: {interface}")
        logging.info(f"Log file: {logfile_name}")

        # Open log file for writing
        with open(logfile_name, 'w') as logfile:
            logfile.write(f"Network Sniffer Log - Interface: {interface}\n")
            logfile.write(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            logfile.write("-" * 50 + "\n\n")

            try:
                # Start packet sniffing
                sniff(iface=interface, 
                      prn=lambda pkt: handle_packet(pkt, logfile),
                      store=0)
            except KeyboardInterrupt:
                logging.info("Packet capture stopped by user")
                sys.exit(0)
            except Exception as e:
                logging.error(f"Error during packet capture: {str(e)}")
                sys.exit(1)

    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        sys.exit(1)

# Check if the script is being run directly
if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python NetworkSniffer.py <interface> [verbose]")
        print("Example: python NetworkSniffer.py \"\\Device\\NPF_{7A7341BF-5180-408A-A41E-FE49AE5872D7}\" verbose")
        print("\nAvailable interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        sys.exit(1)

    verbose = len(sys.argv) == 3 and sys.argv[2].lower() == "verbose"
    main(sys.argv[1], verbose)