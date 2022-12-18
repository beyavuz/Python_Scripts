import binascii
import struct
import socket
import gi
gi.require_version('Notify','0.7')
from gi.repository import Notify


DHCP_MESSAGE_TYPE_OPTION = 53
REQUESTED_IP_ADDRESS_OPTION = 50
CLIENT_IDENTIFIER_OPTION = 61
HOSTNAME_OPTION = 12

DHCP_REQUEST_PACKET = 3
DHCP_DISCOVER_PACKET = 1

Notify.init('test')
lap1 = Notify.Notification.new('Notify_1')
lap2 = Notify.Notification.new('Notify_2')


def ip_v4_format(packed_ip):
    return '.'.join(map(str, packed_ip))


def unpack_ip_header(ip_packet):
    ip_version_header_length = ip_packet[0]
    # get version of ip_header
    ip_version = ip_version_header_length >> 4

    # get header length = count of how many 32 bits there are.
    header_length_how_many_32_bits = ip_version_header_length & 0xf

    # 32 bit = 4 byte , thus we need to multiply by 4
    real_header_length = header_length_how_many_32_bits * 4
    ttl, proto, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', ip_packet[:20])
    return ip_packet[real_header_length:]


def unpack_udp_packet(data):
    src_port, dst_port, size = struct.unpack('!HH2xH', data[:8])
    if src_port == 68 or dst_port == 67:
        unpack_dhcp(data[8:])
#  return src_port, dst_port, data[8:]


def unpack_dhcp(data):
    message_type, _, _, _, _, _, _, client_addr, _, _, _, client_hardware_address, _, _ = struct.unpack(
        '!BBBBLHH4sLLL16s64s128s', data[:236])
    parse_options(data[236:])


def parse_options(paket_options):
    count = 0
    dhcp_request_flag = False
    dhcp_discovery_flag = False
    assigned_ip_address = ""
    mac_address = ""
    hostname = ""
    without_magic = paket_options[4:]  # 4 bytes for magic bytes in DHCP
    # print("paket geldi...",without_magic)
    while len(without_magic) > count:
        try:
            option, option_len = struct.unpack('!BB', without_magic[count:count + 2])
        except struct.error as err:
            break
        temp_format = '!' + str(option_len) + 's'
        try:
            data, = struct.unpack(temp_format, without_magic[count + 2:option_len + count + 2])
        except struct.error as err:
            break
        count = count + (2 + option_len)
        if option == DHCP_MESSAGE_TYPE_OPTION:  # DHCP Message Type
            #      print("message type:", data, "--", len(data))
            if int(binascii.hexlify(data).decode()) == DHCP_REQUEST_PACKET:  # DHCP Request
                dhcp_request_flag = True
            elif int(binascii.hexlify(data).decode()) == DHCP_DISCOVER_PACKET:  # DHCP Discover
                dhcp_discovery_flag = True
        if option == REQUESTED_IP_ADDRESS_OPTION:  # requested IP Address
            #       print(f"Assigned ip address:{socket.inet_ntoa(data)}")
            assigned_ip_address = socket.inet_ntoa(data)
        if option == HOSTNAME_OPTION:  # hostname
            #       print(f"Hostname:{data.decode()}")
            hostname = data.decode()
        if option == CLIENT_IDENTIFIER_OPTION:  # client identifier
            data = data[1:]
            #     print(f"Mac Address:{binascii.hexlify(data, ':').decode()}")
            mac_address = binascii.hexlify(data, ':').decode()

    if dhcp_request_flag:
        print("Atanan ip adresi:", assigned_ip_address)
    if dhcp_discovery_flag or ((not dhcp_discovery_flag) and hostname != '' and mac_address != ''):
        print("Mac adresi:", mac_address)
        print("hostname:", hostname)

    lap1.update("Yeni Host",
                f"""
                MAC:{mac_address}\n
                Atanan ip adresi:{assigned_ip_address}\n
                Hostname:{hostname}
                """)
    lap1.show()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    while True:
        paket, adress = sock.recvfrom(65535)
        unpack_udp_packet(unpack_ip_header(paket))


if __name__ == "__main__":
    main()
