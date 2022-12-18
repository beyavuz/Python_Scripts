import sys

from ethernet_packet import EthernetPacket
from misc_raw_ethernet import *
import argparse
import socket

"""
sudo tcpdump -v -e -s0 ether host <target_mac>
"""

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send raw ethernet packet')
    parser.add_argument('--srcmac', required=False, dest='source_mac', help='Source mac address', default=None)
    parser.add_argument('--dstmac', required=False, dest='destination_mac', help='Destination mac address',
                        type=check_valid_mac_address, default="ff:ff:ff:ff:ff:ff")
    parser.add_argument('--iface', required=True, dest='interface', help='Interface', type=check_interface_is_exist)
    parser.add_argument('--count', required=False, dest='How many packet will be sent', default=1)
    parsed_args = parser.parse_args()
    src_mac, dst_mac, interface_name, count = list(vars(parsed_args).values())
    print(src_mac, dst_mac, interface_name)
    if src_mac is None:
        src_mac = get_hardware_address(interface_name)
        print(src_mac)
    raw_ethernet = EthernetPacket(interface=interface_name, source_mac=src_mac, destination_mac=dst_mac)
    raw_ethernet_packet = raw_ethernet.get_raw_packet()

    # if we need, we add ip header as well.
    # ip_header = IpPacket(source_address, destination_address).create_ip_fields_and_packets()
    # final_packet = ip_header + ethernet_packet

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        # s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
    except socket.error as err:
        print("Error:", err)
        sys.exit()

    s.bind((interface_name, 0))
    for i in range(0,count):
        s.sendall(raw_ethernet_packet)

        print(f"{i + 1}. packet is send")

    print("All packets are send.")
    s.close()
