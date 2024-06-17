Packet Sniffer



A Python-based packet sniffer that captures and analyzes network packets, supporting various protocols including Ethernet, IPv4, TCP, UDP, ICMP, ARP, DNS, HTTP, and FTP.

Table of Contents
Overview
Features
Installation
Usage
Basic Usage
Dynamic Capture Mode
Output Options
Supported Protocols
Contributing
License
Overview
This packet sniffer is a Python script designed for network administrators and cybersecurity enthusiasts to monitor and analyze network traffic. It utilizes raw sockets to capture packets directly from a specified network interface. The captured packets are processed to extract and display detailed information about each packet, including protocol-specific details such as IP addresses, port numbers, and payload data.

Features
Protocol Support: Handles Ethernet, IPv4, TCP, UDP, ICMP, ARP, DNS, HTTP, and FTP protocols.
Dynamic Capture Mode: Allows starting and stopping packet capture dynamically from the command line.
Output Options: Supports saving captured packets to a file in raw, JSON, or PCAP format.
Verbose Logging: Provides detailed logging with options for increased verbosity.
Command-Line Interface: Uses argparse for flexible command-line argument parsing.
Cross-platform: Works on Linux, macOS, and Windows (with appropriate permissions).


Installation
1. Clone the repository:

'''bash
git clone https://github.com/your_username/packet-sniffer.git
cd packet-sniffer '''

2.Install dependencies:

Ensure Python 3.x and necessary libraries are installed. Install dependencies using pip:

'''bash 
pip install -r requirements.txt '''

3. Run the script:

'''bash 
sudo python3 packet_sniffer.py -i <interface> -o <output_file> -f <filter> 
'''

Usage
Basic Usage
Capture packets on a specific network interface (-i or --interface) and optionally save to an output file (-o or --output):

'''bash
sudo python3 packet_sniffer.py -i wlan0 -o captured_packets.txt -f all
'''
Adjust the commands and descriptions based on your specific project details and user requirements.
Output Options
Raw Output: Append raw packet data to a specified file (-o).
JSON Output: Save packet details in JSON format to a file (-o and --json).
PCAP Output: Save captured packets in PCAP format for analysis (--pcap).
Supported Protocols
The packet sniffer supports the following protocols:

Ethernet
IPv4
TCP
UDP
ICMP
ARP
DNS
HTTP
FTP
Contributing
Contributions are welcome! Please fork the repository and create a pull request for any enhancements, bug fixes, or new features. Ensure your code adheres to PEP 8 style guidelines and includes appropriate tests.

Fork the repository (https://github.com/your_username/packet-sniffer/fork)
Create your feature branch (git checkout -b feature/YourFeature)
Commit your changes (git commit -am 'Add some feature')
Push to the branch (git push origin feature/YourFeature)
Create a new Pull Request


