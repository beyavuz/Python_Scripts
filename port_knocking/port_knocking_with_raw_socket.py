import socket
import struct
import argparse
import time


def calculate_checksum(message):
    """
        tcp_pseudo_header + tcp_header + application_data
        or
        udp_pseudo_header + udp_header + application_data
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
    ss = ss + (ss >> 16)
    ss = ~ss & 0xffff
    return ss


def get_ip_address(iface):
    import netifaces
    return netifaces.ifaddresses(iface)[2][0]['addr']


def create_udp_pseudo_header(src_ip, dst_ip, data):
    protocol = socket.IPPROTO_UDP
    zero = 0
    udp_length = 8 + len(data)  # udp header is 8 byte + data_length to be send
    return struct.pack('!4s4sBBH', src_ip, dst_ip, zero, protocol, udp_length)


def create_udp_header(dst_prt, src_ip, dst_ip, data, src_prt=3333):
    udp_length = 8 + len(data)
    udp_pseudo_header = create_udp_pseudo_header(src_ip, dst_ip, data)
    udp_header_for_checksum = struct.pack('!4H', src_prt, dst_prt, udp_length, 0)
    checksum = calculate_checksum(udp_pseudo_header + udp_header_for_checksum + data)
    real_udp_header = struct.pack('!4H', src_prt, dst_prt, udp_length, checksum)
    return real_udp_header


def create_tcp_pseudo_header(src_ip, dst_ip, data, tcp_header_len):
    pseudo_reversed = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = tcp_header_len + len(data)
    return struct.pack('!4s4sBBH', src_ip, dst_ip, pseudo_reversed, protocol, tcp_length)


def create_tcp_packet(dst_port, src_ip, dst_ip, data=b"Hi", src_port=4444, flags="S"):
    tcp_seq = 0
    tcp_ack_seq = 0
    tcp_data_offset = 5
    tcp_data_offset_res = (tcp_data_offset << 4) + 0

    # tcp flags
    tcp_flag_urg = 0
    tcp_flag_ack = 0
    tcp_flag_psh = 0
    tcp_flag_rst = 0
    tcp_flag_syn = 0
    tcp_flag_fin = 0
    flag_set = set(flags)
    for i in flag_set:
        if i == "S":
            tcp_flag_syn = 1
        elif i == "A":
            tcp_flag_ack = 1
        elif i == "U":
            tcp_flag_urg = 1
        elif i == "F":
            tcp_flag_fin = 1
        elif i == "P":
            tcp_flag_psh = 1
        elif i == "R":
            tcp_flag_rst = 1

    tcp_flags_res = tcp_flag_fin + (tcp_flag_syn << 1) + (tcp_flag_rst << 2) + (tcp_flag_psh << 3) + \
                    (tcp_flag_ack << 4) + (tcp_flag_urg << 5)

    tcp_window = socket.htons(5840)
    tcp_checksum_temp = 0
    tcp_urgent_pointer = 0

    tcp_header_without_checksum = struct.pack('!HHIIBBHHH', src_port, dst_port, tcp_seq, tcp_ack_seq,
                                              tcp_data_offset_res, tcp_flags_res, tcp_window, tcp_checksum_temp,
                                              tcp_urgent_pointer)

    tcp_pseudo_header = create_tcp_pseudo_header(src_ip, dst_ip, data, len(tcp_header_without_checksum))
    tcp_checksum = calculate_checksum(tcp_pseudo_header + tcp_header_without_checksum + data)

    # checksum is not internet order
    tcp_real_header = struct.pack('!HHIIBBH', src_port, dst_port, tcp_seq, tcp_ack_seq, tcp_data_offset_res,
                                  tcp_flags_res, tcp_window) \
                      + struct.pack('H', tcp_checksum) \
                      + struct.pack('!H', tcp_urgent_pointer)

    return tcp_real_header


def send_tcp_req(flags, dst_port, dst_ip, data, iface):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    tcp_header = create_tcp_packet(dst_port=dst_port, data=data,
                                   dst_ip=socket.inet_aton(dst_ip),
                                   src_ip=socket.inet_aton(get_ip_address(iface)),
                                   flags=flags)
    sock.sendto(tcp_header + data, (dst_ip, dst_port))


def send_udp_req(dst_port, dst_ip, iface, data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    udp_header = create_udp_header(dst_prt=dst_port,
                                   src_ip=socket.inet_aton(get_ip_address(iface)),
                                   dst_ip=socket.inet_aton(dst_ip),
                                   data=data)
    sock.sendto(udp_header + data, (dst_ip, dst_port))


def main():
    parser = argparse.ArgumentParser(description='Port knocking with raw sockets')
    parser.add_argument('--host', required=True, dest="host_address", help="Host address", default=None)
    parser.add_argument('--ports', required=True, dest="ports", help="Target port(s)", default=None, nargs="+")
    parser.add_argument('--flag', required=False, dest="flags", help="TCP flags to set", default="S")
    parser.add_argument('--iface', required=False, dest="iface", help="Interface", default="lo")
    parser.add_argument('--timeout', required=False, dest="timeout",
                        help="time between each request(milisecond)", default=200, type=int)
    args = parser.parse_args()

    host_address, ports, flags, iface, timeout = list(vars(args).values())

    port_proto = {}
    data = b"Hi"
    for i in ports:
        temp = i.split(":")
        if len(temp) > 1 and temp[1] != "":
            port_proto[int(temp[0])] = temp[1].upper()
        else:
            port_proto[int(temp[0])] = "TCP"

    print("------TARGET------\n" +
          f"  {host_address}  ")

    for item in port_proto.items():
        if item[1] == "TCP":
            print(f"Hitting port:{item[1]} protocol:TCP Flags:{''.join(x for x in ports)}")
            send_tcp_req(flags, item[0], host_address, data, iface)
        else:
            print(f"Hitting port:{item[1]} protocol:UDP")
            send_udp_req(item[0], host_address, iface, data)
        print(f"Wait {timeout / 1000} miliseconds")
        time.sleep(timeout / 1000)


if __name__ == "__main__":
    main()
