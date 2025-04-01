# Network Packet Sniffer

A Python-based network packet sniffer that captures and analyzes network traffic in real-time. This tool allows you to monitor network activity, capture IP and TCP packets, and log detailed information about network communications.

## Features

- Real-time packet capture and analysis
- Detailed packet information logging including:
  - Source and destination IP addresses
  - Protocol information
  - Packet length and TTL
  - TCP-specific details (ports, flags, sequence numbers)
- Timestamp-based logging
- Support for multiple network interfaces
- Windows and Unix-like system compatibility
- Verbose logging option for debugging

## Prerequisites

- Python 3.x
- Scapy library
- Npcap or WinPcap (for Windows)
- Administrator/root privileges

## Installation

1. Clone this repository or download the source code
2. Install required Python packages:
   ```bash
   pip install scapy netifaces
   ```
3. Install Npcap (for Windows):
   - Download Npcap from: https://npcap.com/#download
   - Run the installer with default settings

## Usage

1. Run the interface list script to see available network interfaces:
   ```bash
   python list_interfaces.py
   ```

2. Run the network sniffer with administrator privileges:
   ```bash
   # On Windows
   python NetworkSniffer.py "\Device\NPF_{YOUR-INTERFACE-ID}"
   
   # On Unix-like systems
   sudo python NetworkSniffer.py eth0
   ```

3. Optional: Enable verbose mode by adding "verbose" as the second argument:
   ```bash
   python NetworkSniffer.py "\Device\NPF_{YOUR-INTERFACE-ID}" verbose
   ```

4. Press Ctrl+C to stop the packet capture

## Output

The sniffer creates a log file with the following naming convention:
```
sniffer_{INTERFACE-ID}_{TIMESTAMP}.txt
```

Each log entry contains:
- Timestamp
- Source and destination IP addresses
- Protocol information
- Packet length and TTL
- TCP-specific details (if applicable)

## Security Note

This tool requires administrator/root privileges to capture network packets. Use responsibly and in accordance with your network's security policies and local regulations.

## Troubleshooting

1. If you get "Interface not found" error:
   - Make sure you're using the correct interface ID
   - Verify you have administrator privileges
   - Check if Npcap/WinPcap is installed properly

2. If no packets are being captured:
   - Verify the interface is active
   - Check if there's network traffic on the interface
   - Ensure no firewall is blocking the capture

## License

This project is open source and available under the MIT License.

## Author

Arsany Ehab

## Acknowledgments

- Scapy library and its contributors
- Npcap/WinPcap developers 