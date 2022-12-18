import socket
import struct
import binascii


def get_mac_address(mac_adress_binary_format):
    return binascii.hexlify(mac_adress_binary_format, ':').decode().upper()


# unpack ethernet frame
def ethernet_frame(frame):
    dst_mac, src_mac, eth_type = struct.unpack('!6s6sH', frame[:14])
    return get_mac_address(dst_mac), get_mac_address(src_mac), socket.htons(eth_type), frame[14:]


def ip_v4_format(packed_ip):
    return '.'.join(map(str, packed_ip))


# unpack icmp header
def icmp_packet(data):
    icmp_type, code, icmp_checksum = struct.unpack('!BBH', data[:4])
    return icmp_type, code, icmp_checksum, data[4:]


# unpack tcp packet
def tcp_segment(data):
    (src_port, dst_port,
     sequence_number, acknowledge_number, offset_reversed_flags) = struct.unpack('!HHLLH', data[:14])

    offset = (offset_reversed_flags >> 12) * 4
    reversed = (offset_reversed_flags >> 6) & 0x3f

    # all flags
    flags = offset_reversed_flags & 0x3f
    urg_flag = flags >> 5
    ack_flag = (flags >> 4) & 0x1
    psh_flag = (flags >> 3) & 0x1
    rst_flag = (flags >> 2) & 0x1
    syn_flag = (flags >> 1) & 0x1
    fin_flags = flags & 0x1

    return src_port, dst_port, sequence_number, acknowledge_number, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flags, data[
                                                                                                                                 offset:]


def udp_packet(data):
    src_port, dst_port, size = struct.unpack('!HH2xH', data[:8])
    return src_port, dst_port, data[8:]


def unpacks_ipv4(ip_packet):
    # gelen packet  b'\x86\x00\x01\xa3\x43\xfa\xfd....'  diyedir.
    """
        ilk 4 bit version ikinci ilk 4 bit ihl , yani ilk byte version+ihl'dir.
        o yüzden ip_packet[0] dersek gelen ilk byte'ı alırız.
    :param ip_packet:
    :return:
    """

    ip_version_header_length = ip_packet[0]
    # get version of ip_header
    ip_version = ip_version_header_length >> 4

    # get header length = count of how many 32 bits there are.
    header_length_how_many_32_bits = ip_version_header_length & 0xf

    # 32 bit = 4 byte , thus we need to multiply by 4
    real_header_length = header_length_how_many_32_bits * 4

    # unpack packet
    """
        ilk 20 byte'ı alıyorum,20 byte'tan sonra options ve padding var onları almıyorum.
        x -> padding byte, null byte , 
            unpack ederken işte ilk baştaki şu kadar byte'ı ele alma. anlamında.
        8x -> version,ihl,type of service,total length, -> 4 bytes 
                identification, flags,fragment offset  -> 4 bytes
                8x -> 8 bytes
    """
    ttl, proto, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', ip_packet[:20])
    return ip_version, real_header_length, ttl, proto, ip_v4_format(src_ip), ip_v4_format(dest_ip), ip_packet[
                                                                                                    real_header_length:]


def arp_packet_unpack(data):
    # arp packet size 28
    # first 14 bytes for ethernet frame header
    (hardware_type, protocol_type, hardware_address_length, protocol_address_length, opcode, sender_mac_address
     , sender_ip_address, target_mac_address, target_ip_address) = struct.unpack('=2s2sBB2s6s4s6s4s', data[0:28])
    # return struct.unpack('!2s2s1s1s2s6s4s6s4s', data[0:28])
    # struct.unpack('=HHBBH6sI6sI', data[0:28])
    return (hardware_type, protocol_type, hardware_address_length, protocol_address_length, opcode, get_mac_address(sender_mac_address)
            , socket.inet_ntoa(sender_ip_address), get_mac_address(target_mac_address), socket.inet_ntoa(target_ip_address))


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    count = 0
    while True:

        """
        raw_data,address = s.recvfrom(65535)
        print(raw_data ,"\n\n and address:",address)
        """
        raw_data = s.recv(65535)  # theoretical maximum size of an IP packet
        dst_mac, src_mac, eth_type, data_from_frame = ethernet_frame(raw_data)
        # print("****************_ETHERNET_FRAME_****************")
        # print(f'src_mac:{src_mac} , dst_mac:{dst_mac} ,  protocol:{eth_type}')
        # 8 stand for ip_v4
        print("eth type:", eth_type)
        if eth_type == 8:
            (version, header_length, ttl, proto, src, target, data_from_ip) = unpacks_ipv4(data_from_frame)
            print("****************_IP_PACKET_****************")
            print(f"version:{version}, protocol:{proto} \n"
                  f"Source_Ip:{src}, Target_Ip:{target}")

            if proto == 0x06:  # TCP
                (src_port, dst_port, _, _, urg, ack, psh, rst, syn, fin, data_from_tcp) = tcp_segment(data_from_ip)
                print("****************_TCP_PAYLOAD_****************")
                print(f"source_port:{src_port} , dst_port:{dst_port}\n"
                      f"Flags:\n"
                      f"\tUrg:{urg}\n"
                      f"\tAck:{ack}\n"
                      f"\tPsh:{psh}\n"
                      f"\tRst:{rst}\n"
                      f"\tSyn:{syn}\n"
                      f"\tFin:{fin}\n")
                print(f"data:{data_from_tcp}")
            elif proto == 0x11:  # UDP
                (src_port, dst_port, data_from_udp) = udp_packet(data_from_ip)
                print("****************_UDP_PAYLOAD_****************")
                print(f"src_port:{src_port}  , dst_port:{dst_port}")
                print(f"data:{data_from_udp}")
            elif proto == 0x01:  # ICMP
                (icmp_type, icmp_code, icmp_checksum, payload_icmp) = icmp_packet(data_from_ip)
                print("****************_ICMP_PACKET_****************")
                print(f"icmp_type:{icmp_type}\n"
                      f"icmp_code:{icmp_code}\n"
                      f"icmp_code:{icmp_checksum}\n"
                      f"data:{payload_icmp}")

        elif eth_type == 1544:  # ARP Packet eth_type == b'\x08\x06'
            (hardware_type, protocol_type, hardware_address_length, protocol_address_length, opcode, sender_mac_address
             , sender_ip_address, target_mac_address, target_ip_address) = arp_packet_unpack(data_from_frame)
            print("****************_ARP_PACKET_****************")
            print(f"Hardware type:  {hardware_type}\n"
                  f"Protocol type:  {protocol_type}\n"
                  f"Hardware size:  {hardware_address_length}\n"
                  f"Protocol size:  {protocol_address_length}\n"
                  f"Opcode:         {opcode}\n"
                  f"Source mac:     {sender_mac_address}\n"
                  f"Source IP:      {sender_ip_address}\n"
                  f"Dest MAC:       {target_mac_address}\n"
                  f"Dest IP:        {target_ip_address}\n")
            print("-------------------------------------------------------------\n\n"
                  "-----------------------------------------------------------------")


main()
