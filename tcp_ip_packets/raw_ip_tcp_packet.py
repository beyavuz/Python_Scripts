import random
import socket
import struct
import sys
# from Crypto.Random  import random
import random
import binascii


class TcpPacket:
    def __init__(self, src_ip_address, dest_ip_address, src_port, dest_port, data='',
                 urg_flag=0, ack_flag=0, psh_flag=0, rst_flag=0, syn_flag=1, fin_flag=0):
        self.tcp_src_ip = src_ip_address
        self.tcp_dest_ip = dest_ip_address
        self.src_port = src_port
        self.dest_port = dest_port
        self.application_data = data
        self.configure_flags(urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag)
        self.flags_res = self.create_flags_res()
        self.set_headers_fields()
        self.tcp_header_without_checksum = self.create_tcp_header_without_checksum()
        self.tcp_pseudo_header = self.create_tcp_pseudo_header()
        self.tcp_checksum = self.calculate_checksum(self.tcp_pseudo_header + self.tcp_header_without_checksum +
                                                    self.application_data.encode('utf-8'))

    # self.tcp_header_with_checksum = self.create_tcp_header_with_checksum()

    def configure_flags(self, urg, ack, psh, rst, syn, fin):
        self.urg = urg
        self.ack = ack
        self.psh = psh
        self.rst = rst
        self.syn = syn
        self.fin = fin

    def create_flags_res(self):
        return self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + \
               (self.ack << 4) + (self.urg << 5)

    def set_headers_fields(self):
        self.tcp_seq = 0
        self.tcp_ack_seq = 0
        self.tcp_data_offset = (5 << 4)  # 80
        self.tcp_window = socket.htons(5840)
        self.tcp_urgent_pointer = 0

    def create_tcp_header_without_checksum(self):
        checksum = 0
        return struct.pack('!HHIIBBHHH', self.src_port, self.dest_port, self.tcp_seq, self.tcp_ack_seq,
                           self.tcp_data_offset,
                           self.flags_res, self.tcp_window, checksum,
                           self.tcp_urgent_pointer)

    def create_tcp_pseudo_header(self):
        src_ip_address = socket.inet_aton(self.tcp_src_ip)
        dst_ip_address = socket.inet_aton(self.tcp_dest_ip)
        pseudo_reversed = 0
        protocol = socket.IPPROTO_TCP  # 6
        tcp_length = len(self.tcp_header_without_checksum) + len(self.application_data)

        return struct.pack('!4s4sBBH', src_ip_address, dst_ip_address, pseudo_reversed, protocol, tcp_length)

    def calculate_checksum(self, message):
        """
            tcp_pseudo_header + tcp_header + application_data
        :param message:
        :return:
        """
        ss = 0
        for i in range(0, len(message), 2):
            if message[i + 1] == len(message):
                ss += message[i]
            else:
                w = (message[i + 1] << 8) + message[i]
                ss += w

        ss = (ss >> 16) + (ss & 0xffff)

        # 1'e tümleyen
        ss = ss + (ss >> 16)
        ss = ~ss & 0xffff
        print("checksum :", ss)
        return ss

    def create_tcp_header_with_checksum(self):
        part_one = struct.pack('!HHIIBBH', self.src_port, self.dest_port, self.tcp_seq, self.tcp_ack_seq,
                               self.tcp_data_offset, self.flags_res, self.tcp_window)

        # checksum is not in internet byte order
        part_two = struct.pack('H', self.tcp_checksum)
        part_three = struct.pack('!H', self.tcp_urgent_pointer)
        return part_one + part_two + part_three


class IpPacket:

    def __init__(self, src_ip_address, dst_ip_address):
        self.src_ip_address = socket.inet_aton(src_ip_address)
        self.dst_ip_address = socket.inet_aton(dst_ip_address)

    # self.raw_ip_packet_header = self.create_ip_fields_and_packets()

    def create_ip_fields_and_packets(self):
        self.ip_version = 4
        self.ihl = 5
        self.ip_tos = 0
        self.ip_tot_len = 0
        self.ip_id = random.randint(1, 65535)
        # self.ip_id = random.getrandbits(16)
        self.ip_frag_offset = 0
        self.ip_ttl = 255
        self.ip_proto = socket.IPPROTO_TCP
        self.ip_checksum = 0
        ip_version_and_ihl = (self.ip_version << 4) + self.ihl
        return struct.pack('!BBHHHBBH4s4s', ip_version_and_ihl, self.ip_tos, self.ip_tot_len, self.ip_id,
                           self.ip_frag_offset, self.ip_ttl, self.ip_proto, self.ip_checksum, self.src_ip_address,
                           self.dst_ip_address)


if __name__ == '__main__':
    try:
        # s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    except socket.error as err:
        print("Error:", err)
        sys.exit()

    user_data = "merhaba duny"
    source_address = '192.168.1.37'
    destination_address = '192.168.1.1'
    source_port = 9876
    destination_port = 9999
    ip_header = IpPacket(source_address, destination_address).create_ip_fields_and_packets()
    tcp_header = TcpPacket(source_address, destination_address, source_port, destination_port, user_data) \
        .create_tcp_header_with_checksum()

    """
        # TCP and IP header
        final_packet = ip_header + tcp_header + user_data.encode('utf-8')
        print("Final packet to send:", final_packet)
        s.sendto(final_packet, (destination_address, 0))
    """
    ethernet_packet = EthernetPacket()
    final_packet = ethernet_packet.raw_ethernet_packet + ip_header
    # s.sendto(final_packet, ('192.168.1.1', 0))
    s.bind(('wlp3s0',0))
    s.sendall(final_packet)
