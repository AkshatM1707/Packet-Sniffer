import socket
import struct
import textwrap
import argparse
import logging
import threading
import json
import os

# Define tab spacing for formatting output
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

stop_event = threading.Event()

def main():
    args = parse_arguments()
    setup_logging(args.verbose)

    try:
        connection = create_socket(args.interface)
        logging.info("Socket created successfully.")
    except PermissionError:
        logging.error("Permission denied: You need to run this script as root.")
        return
    except Exception as e:
        logging.error(f"Error creating socket: {e}")
        return

    if args.dynamic:
        logging.info("Starting dynamic packet capture mode. Type 'start' to begin capturing and 'stop' to end.")
        while True:
            command = input("> ").strip().lower()
            if command == "start":
                start_capture(connection, args)
            elif command == "stop":
                stop_capture()
            elif command == "exit":
                if stop_event.is_set():
                    stop_capture()
                break
            else:
                logging.info("Unknown command. Available commands: 'start', 'stop', 'exit'")
    else:
        capture_packets(connection, args)

def parse_arguments():
    parser = argparse.ArgumentParser(description="A simple packet sniffer.")
    parser.add_argument('-i', '--interface', type=str, required=True, help="Network interface to listen on")
    parser.add_argument('-f', '--filter', type=str, choices=['all', 'tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'ftp'], default='all', help="Type of packets to capture")
    parser.add_argument('-o', '--output', type=str, help="Output file to save captured packets")
    parser.add_argument('-v', '--verbose', action='store_true', help="Increase output verbosity")
    parser.add_argument('-d', '--dynamic', action='store_true', help="Enable dynamic start/stop of packet capture")
    parser.add_argument('--json', action='store_true', help="Output captured packets in JSON format")
    parser.add_argument('--pcap', action='store_true', help="Output captured packets in PCAP format")
    return parser.parse_args()

def setup_logging(verbose):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format='%(message)s', level=level)

def create_socket(interface):
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    connection.bind((interface, 0))
    return connection

def capture_packets(connection, args):
    packet_count = 0

    while not stop_event.is_set():
        try:
            raw_data, addr = connection.recvfrom(65535)
            if raw_data:
                packet_count += 1
                process_packet(raw_data, args)
            else:
                logging.info("No data received.")
        except Exception as e:
            logging.error(f"Error receiving data: {e}")

    logging.info(f"Captured {packet_count} packets.")

def start_capture(connection, args):
    if not stop_event.is_set():
        stop_event.clear()
        capture_thread = threading.Thread(target=capture_packets, args=(connection, args))
        capture_thread.start()
        logging.info("Packet capture started.")
    else:
        logging.info("Packet capture is already running.")

def stop_capture():
    if not stop_event.is_set():
        logging.info("Packet capture is not running.")
    else:
        stop_event.set()
        logging.info("Stopping packet capture...")

def process_packet(raw_data, args):
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    packet_data = {
        "Ethernet Frame": {
            "Destination": dest_mac,
            "Source": src_mac,
            "Protocol": eth_proto,
        }
    }
    logging.info("\nEthernet Frame:")
    logging.info(f"{TAB_1}Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

    if eth_proto == 8:  # IPv4
        version, header_len, ttl, proto, src, target, data = ipv4_packet(data)
        packet_data["IPv4 Packet"] = {
            "Version": version,
            "Header Length": header_len,
            "TTL": ttl,
            "Protocol": proto,
            "Source": src,
            "Target": target,
        }
        logging.info(f"{TAB_1}IPv4 Packet:")
        logging.info(f"{TAB_2}Version: {version}, Header Length: {header_len}, TTL: {ttl}")
        logging.info(f"{TAB_2}Protocol: {proto}, Source: {src}, Target: {target}")

        if proto == 1 and (args.filter in ['all', 'icmp']):  # ICMP
            icmp_type, code, checksum, data = icmp_packet(data)
            packet_data["ICMP Packet"] = {
                "Type": icmp_type,
                "Code": code,
                "Checksum": checksum,
                "Data": format_multi_line(DATA_TAB_3, data)
            }
            logging.info(f"{TAB_1}ICMP Packet:")
            logging.info(f"{TAB_2}Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
            logging.info(f"{TAB_2}Data:")
            logging.info(format_multi_line(DATA_TAB_3, data))

        elif proto == 6 and (args.filter in ['all', 'tcp']):  # TCP
            src_port, dest_port, sequence, acknowledgment, flags_urg, flags_ack, flags_psh, flags_rst, flags_syn, flags_fin, data = tcp_segment(data)
            packet_data["TCP Segment"] = {
                "Source Port": src_port,
                "Destination Port": dest_port,
                "Sequence": sequence,
                "Acknowledgment": acknowledgment,
                "Flags": {
                    "URG": flags_urg,
                    "ACK": flags_ack,
                    "PSH": flags_psh,
                    "RST": flags_rst,
                    "SYN": flags_syn,
                    "FIN": flags_fin,
                },
                "Data": format_multi_line(DATA_TAB_3, data)
            }
            logging.info(f"{TAB_1}TCP Segment:")
            logging.info(f"{TAB_2}Source Port: {src_port}, Destination Port: {dest_port}")
            logging.info(f"{TAB_2}Sequence: {sequence}, Acknowledgment: {acknowledgment}")
            logging.info(f"{TAB_2}Flags:")
            logging.info(f"{TAB_3}URG: {flags_urg}, ACK: {flags_ack}, PSH: {flags_psh}, RST: {flags_rst}, SYN: {flags_syn}, FIN: {flags_fin}")
            logging.info(f"{TAB_2}Data:")
            logging.info(format_multi_line(DATA_TAB_3, data))

            if dest_port == 80 and (args.filter in ['all', 'http']):  # HTTP
                headers, body = http_packet(data)
                packet_data["HTTP Packet"] = {
                    "Headers": headers,
                    "Body": format_multi_line(DATA_TAB_3, body)
                }
                logging.info(f"{TAB_1}HTTP Packet:")
                logging.info(f"{TAB_2}Headers: {headers}")
                logging.info(f"{TAB_2}Body:")
                logging.info(format_multi_line(DATA_TAB_3, body))

        elif proto == 17 and (args.filter in ['all', 'udp']):  # UDP
            src_port, dest_port, length, data = udp_segment(data)
            packet_data["UDP Segment"] = {
                "Source Port": src_port,
                "Destination Port": dest_port,
                "Length": length,
                "Data": format_multi_line(DATA_TAB_3, data)
            }
            logging.info(f"{TAB_1}UDP Segment:")
            logging.info(f"{TAB_2}Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}")
            logging.info(f"{TAB_2}Data:")
            logging.info(format_multi_line(DATA_TAB_3, data))

            if dest_port == 53 and (args.filter in ['all', 'dns']):  # DNS
                transaction_id, flags, questions, answer_rr, authority_rr, additional_rr, data = dns_packet(data)
                packet_data["DNS Packet"] = {
                    "Transaction ID": transaction_id,
                    "Flags": flags,
                    "Questions": questions,
                    "Answer RRs": answer_rr,
                    "Authority RRs": authority_rr,
                    "Additional RRs": additional_rr,
                    "Data": format_multi_line(DATA_TAB_3, data)
                }
                logging.info(f"{TAB_1}DNS Packet:")
                logging.info(f"{TAB_2}Transaction ID: {transaction_id}, Flags: {flags}")
                logging.info(f"{TAB_2}Questions: {questions}, Answer RRs: {answer_rr}, Authority RRs: {authority_rr}, Additional RRs: {additional_rr}")
                logging.info(f"{TAB_2}Data:")
                logging.info(format_multi_line(DATA_TAB_3, data))

        else:
            logging.info(f"{TAB_1}Data:")
            logging.info(format_multi_line(DATA_TAB_2, data))

    elif eth_proto == 1544 and (args.filter in ['all', 'arp']):  # ARP
        hardware_type, protocol_type, hardware_size, protocol_size, opcode, src_mac, src_ip, dest_mac, dest_ip = arp_packet(data)
        packet_data["ARP Packet"] = {
            "Hardware Type": hardware_type,
            "Protocol Type": protocol_type,
            "Hardware Size": hardware_size,
            "Protocol Size": protocol_size,
            "Opcode": opcode,
            "Source MAC": src_mac,
            "Source IP": src_ip,
            "Destination MAC": dest_mac,
            "Destination IP": dest_ip,
        }
        logging.info(f"{TAB_1}ARP Packet:")
        logging.info(f"{TAB_2}Hardware Type: {hardware_type}, Protocol Type: {protocol_type}, Hardware Size: {hardware_size}, Protocol Size: {protocol_size}")
        logging.info(f"{TAB_2}Opcode: {opcode}")
        logging.info(f"{TAB_2}Source MAC: {src_mac}, Source IP: {src_ip}, Destination MAC: {dest_mac}, Destination IP: {dest_ip}")

    if args.output:
        if args.json:
            with open(args.output, 'a') as f:
                f.write(json.dumps(packet_data, indent=4) + '\n')
        else:
            with open(args.output, 'a') as f:
                f.write(f"{raw_data}\n")

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.ntohs(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

def ipv4_packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    (src_port, dest_port, seq, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)
    return src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

def arp_packet(data):
    hardware_type, protocol_type, hardware_size, protocol_size, opcode, src_mac, src_ip, dest_mac, dest_ip = struct.unpack('! H H B B H 6s 4s 6s 4s', data[:28])
    return hardware_type, protocol_type, hardware_size, protocol_size, opcode, get_mac_addr(src_mac), ipv4(src_ip), get_mac_addr(dest_mac), ipv4(dest_ip)

def dns_packet(data):
    transaction_id, flags, questions, answer_rr, authority_rr, additional_rr = struct.unpack('! H H H H H H', data[:12])
    return transaction_id, flags, questions, answer_rr, authority_rr, additional_rr, data[12:]

def http_packet(data):
    try:
        headers, body = data.split(b'\r\n\r\n', 1)
        headers = headers.decode()
        return headers, body
    except ValueError:
        return data.decode(), b''

def ftp_packet(data):
    try:
        data_str = data.decode()
        command, params = data_str.split(' ', 1)
        return command, params
    except ValueError:
        return data_str, ''

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == "__main__":
    main()
