import binascii
import socket
import struct
import fcntl
import re
import array

__all__ = ['ETH_ALEN', 'ETH_TLEN', 'ETH_HLEN', 'ETH_ZLEN', 'ETH_DATA_LEN', 'ETH_FRAME_LEN', 'ETH_P_ALL',
           'ETH_P_IP', 'ETH_P_ARP','ETH_P_802_EX1' ,'get_hardware_address', 'check_valid_mac_address', 'check_interface_is_exist',
           'convert_byte_to_str_mac_address']

""""
ioctl system call numbers
"""
_SIOCGIFNAME = 0x8910  # get interface name
_SIOCGIFCONF = 0x8912  # get iface list
_SIOCGIFADDR = 0x8915  # get ip address
_SIOCGIFBRDADDR = 0x8919  # get broadcast ip address
_SIOCGIFNETMASK = 0x891b  # get network mask
_SIOCSIFHWADDR = 0x8927  # get hardware address

"""
Ethernet constant
"""
ETH_ALEN = 6  # Octets in one hardware address
ETH_TLEN = 2  # Octets in ethernet type field
ETH_HLEN = 14  # Total octets in header.
ETH_ZLEN = 60  # Min. octets in frame
ETH_DATA_LEN = 1500  # Max. octets in payload
ETH_FRAME_LEN = 1514  # Max. octets in frame

"""
Ethernet protocols , ethernet types
"""
ETH_P_ALL = 0x0003  # All packet
ETH_P_IP = 0x0800  # Internet Protocol packet
ETH_P_ARP = 0x0806  # Address Resolution packet
ETH_P_802_EX1 = 0x88B5  # Local Experimental Ethertype


def _mac_address_format(mac_address):
    formatted_mac_address = ''
    for i in range(1, len(mac_address), 2):
        formatted_mac_address += mac_address[i - 1:i + 1]
        if i + 2 < len(mac_address):
            formatted_mac_address += ':'
        else:
            break
    return formatted_mac_address


def get_hardware_address(interface, is_byte=False):
    """ get mac address of given interface """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    hardware_info = _get_info(s, interface, _SIOCSIFHWADDR)
    hardware_address = hardware_info[18:24]
    print("hardware:", _mac_address_format(binascii.hexlify(hardware_address).decode()))
    if len(hardware_address) != ETH_ALEN:
        raise ValueError()
    return hardware_address if is_byte else _mac_address_format(
        binascii.hexlify(hardware_address).decode())


def get_mac_address(interface, port=0):
    """ second way to get mac address of given interface """
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface, port))
    mac_address_binary = s.getsockname()[4]
    s.close()
    return _mac_address_format(binascii.hexlify(mac_address_binary).decode('utf-8'))


def _get_info(sock, interface, option):
    return fcntl.ioctl(sock.fileno(), option, struct.pack('256s', interface[:15].encode()))


def check_valid_mac_address(mac_address):
    if re.match(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$', mac_address):
        return mac_address
    elif re.match(r'^([0-9A-Fa-f]{2}-){5}([0-9A-Fa-f]{2})$', mac_address):
        mac_address.replace('-', ':')
        return mac_address
    else:
        raise ValueError('invalid format')


"""
def get_interfaces_with_ifaces():
    import netifaces
    return netifaces.interfaces()
"""


def _get_interfaces():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interfaces_names_binary = array.array('B', 1024 * b'\0')
    array_address, _ = interfaces_names_binary.buffer_info()
    packed_buffer = struct.pack('iL', 1024, array_address)

    # ioctl system call (data will be written on the variable named interfaces_names_binary, cuz its address was given.
    coming_data_packed = fcntl.ioctl(s, _SIOCGIFCONF, packed_buffer)
    max_length_out, address_out = struct.unpack('iL', coming_data_packed)

    # insufficient array size
    if max_length_out <= 0:
        raise ValueError()
    interface_names = interfaces_names_binary.tobytes()[:max_length_out]
    interface_dict = {}
    for i in range(0, max_length_out, 40):
        # get interface name
        name = interface_names[i:i + 16].split(b'\0', 1)[0].decode('utf-8')
        # ip address
        ip_addr = interface_names[i + 20:i + 24]
        interface_dict[name] = ".".join(map(str, struct.unpack('BBBB', ip_addr)))

    """
        for key, item in interface_dict.items():
            print(key, '---', item)
            <interface> --- <ip_address>
        """

    return interface_dict


def check_interface_is_exist(interface_name):
    all_interfaces = _get_interfaces()
    if interface_name not in all_interfaces.keys():
        raise ValueError()
    return interface_name


def convert_byte_to_str_mac_address(mac_address):
    return _mac_address_format(binascii.hexlify(mac_address).decode('utf-8'))
