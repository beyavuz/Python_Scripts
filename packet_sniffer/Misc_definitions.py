import binascii
import struct
from socket import inet_aton, inet_ntoa


def ip_v4_converter_to_bytes(ip_adress="192.168.1.1"):
    return inet_aton(ip_adress)


# 1.yol packed value to string
def ip_v4_converter_to_string():
    ip_address_packed = ip_v4_converter_to_bytes()
    return inet_ntoa(ip_address_packed)


# 2.yol packed_value to string
def ip_v4_converter_to_string_v2():
    ip_address_packed = ip_v4_converter_to_bytes()
    # unpacked_ip_address = struct.unpack('4s', ip_address_packed)
    return '.'.join(map(str, ip_address_packed))


