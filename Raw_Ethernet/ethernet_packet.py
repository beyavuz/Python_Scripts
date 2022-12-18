import struct
import socket
import binascii
from misc_raw_ethernet import *


class EthernetPacket:

    def __init__(self, interface, source_mac, destination_mac='ff:ff:ff:ff:ff:ff', protocol=ETH_P_802_EX1):
        self.interface = interface
        self.src_mac = source_mac
        self.dest_mac = destination_mac
        self.protocol = protocol
        self.raw_ethernet_packet = self.create_raw_ethernet_packet()

    def create_raw_ethernet_packet(self):
        src_mac_res = binascii.unhexlify(self.src_mac.replace(':', ''))
        dst_mac_res = binascii.unhexlify(self.dest_mac.replace(':', ''))
        payload = b'Hi'

        return struct.pack('!6s6sH2s', dst_mac_res,src_mac_res, self.protocol,payload)

    def get_raw_packet(self):
        return self.raw_ethernet_packet
