import socket
import struct
import sys
import time

# karakter sayısı 2'nin katı olmayınca hata veriyor, düzelt.
def calculate_checksum(message):
    s = 0
    print("len message:", len(message))
    for i in range(0, len(message), 2):
        #  w = (ord(message[i + 1]) << 8) + ord(message[i])
        print("message[i]:", message[i])
        print("message[i+1]:", message[i + 1])
        # python3'de ord almaya gerek yok.
        w = (message[i + 1] << 8) + message[i]
        s += w

    s = (s >> 16) + (s & 0xffff)

    # 1'e tümleyen
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s


def create_ip_header(src_ip, dst_ip):
    """ IP HEADER """

    # ip version , 4 for ipv4
    ip_version = 4

    # internet header length, min=5  max=15
    ip_ihl = 5

    # 8 bite tamamlayalım diye
    total = (ip_version << 4) + ip_ihl
    #  (ip_version << 4) | ip_ihl

    # type of service
    ip_tos = 0

    # total length , toplam datagram boyutu
    ip_tot_len = 0  # kernel otomatik olarak dolduracak burayı

    # identification
    ip_id = 54321  # packetin idsi

    # fragment offset
    ip_frag_off = 0

    # ttl , 16 bits thus max=255
    ip_ttl = 255

    # internet protocols, IP protocols
    ip_proto = socket.IPPROTO_TCP

    # checksum
    ip_checksum = 0  # kernel bizim için otomatik olarak dolduracak.

    # source address
    # SYN flood yaparsak, source adresi  spoof yapabiliriz.
    ip_source_address = socket.inet_aton(src_ip)

    # destination address
    ip_destination_address = socket.inet_aton(dst_ip)

    # tüm bu bilgileri binary olarak pack edelim.
    ip_header = struct.pack('!BBHHHBBH4s4s', total, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto,
                            ip_checksum,
                            ip_source_address, ip_destination_address)
    return ip_header


def create_tcp_header(src_port, dst_port, checksum=0):
    """ TCP HEADER  """

    tcp_seq = 454

    tcp_ack_seq = 0

    tcp_data_offset = 5  # 4 bit field , size of tcp header , 5 * 4 = 20

    # tcp_data_offset    normalde 4 bit ben onu 8 bit yapıyorum.
    tcp_data_offset_res = (tcp_data_offset << 4) + 0

    # tcp flags
    tcp_flag_urg = 0
    tcp_flag_ack = 0
    tcp_flag_psh = 0
    tcp_flag_rst = 0
    tcp_flag_syn = 1
    tcp_flag_fin = 0

    """
        flaglar bir bit, dolayısıyla bunları shift ederek birbirlerine ekleyeceğiz.
        son flag'den başlayarak ekliyoruz.
    """

    tcp_flags_res = tcp_flag_fin + (tcp_flag_syn << 1) + (tcp_flag_rst << 2) + (tcp_flag_psh << 3) + \
                    (tcp_flag_ack << 4) + (tcp_flag_urg << 5)

    tcp_window = socket.htons(5840)
    tcp_checksum = checksum
    tcp_urgent_pointer = 0

    # tüm bu bilgileri binary olarak pack edelim.
    if not checksum:
        tcp_header = struct.pack('!HHIIBBHHH', src_port, dst_port, tcp_seq, tcp_ack_seq,
                                 tcp_data_offset_res, tcp_flags_res, tcp_window, tcp_checksum, tcp_urgent_pointer)
    else:
        # checksum internet byte order'ında olmaz.
        temp_part1 = struct.pack('!HHIIBBH', src_port, dst_port, tcp_seq, tcp_ack_seq,
                                 tcp_data_offset_res, tcp_flags_res, tcp_window)

        # checksum internet byte order'ında olmaz, normal şekilde yapıyoruz.
        temp_part2 = struct.pack('H', tcp_checksum)
        temp_part3 = struct.pack('!H', tcp_urgent_pointer)
        tcp_header = temp_part1 + temp_part2 + temp_part3

    return tcp_header


def create_pseudo_tcp_header(source_ip_address, destination_ip_address, len_tcp_header, len_user_data=0):
    """pseudo tcp header
    checksum burada hesaplanır
    tcp pseudo header; tcp header'dan ve biraz da ip header'dan bilgiler barındırır."""

    src_address = socket.inet_aton(source_ip_address)
    dst_address = socket.inet_aton(destination_ip_address)
    pseudo_reversed = 0

    # TCP ise 6 değeri verilir. yada direkt socket'ten çekeriz.
    protocol = socket.IPPROTO_TCP

    tcp_length = len_tcp_header + len_user_data

    pseudo_tcp_header = struct.pack('!4s4sBBH', src_address, dst_address, pseudo_reversed, protocol, tcp_length)

    return pseudo_tcp_header


def main():
    # SOCK_RAW => raw socket
    # IPPROTO_RAW => raw ip packet
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as err:
        print("Error:", err)
        sys.exit()

    # bizde başta socket oluştururken IPPROTO_RAW  dediğimiz için aşağıdaki satırı dememize gerek yok.
    # normalde bu satır kernel'a sen ip_header oluşturma , ben oluşturcam demektir.
    # s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

    source_ip = "192.168.1.37"
    destination_ip = "192.168.1.1"

    src_port = 5432
    dst_port = 9999

    ip_header = create_ip_header(source_ip, destination_ip)

    tcp_header = create_tcp_header(src_port, dst_port)

    # iletilcek user data
    user_data = "merhaba duny"

    pseudo_tcp_header = create_pseudo_tcp_header(source_ip, destination_ip, len(tcp_header), len(user_data))

    tcp_checksum = calculate_checksum(pseudo_tcp_header + tcp_header + user_data.encode('utf-8'))
    tcp_header_with_checksum = create_tcp_header(src_port, dst_port, tcp_checksum)

    final_packet = ip_header + tcp_header_with_checksum + user_data.encode('utf-8')

    print("final packet:\n", final_packet)

    count = 3

    for i in range(count):
        print
        'sending packet...'
        # Send the packet finally - the port specified has no effect
        s.sendto(final_packet, (destination_ip, 0))  # put this in a loop if you want to flood the target
        print
        'send'
        time.sleep(1)

    print('tüm paketler yollandı.')


main()
