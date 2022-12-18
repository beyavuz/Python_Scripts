import socket

from scapy.all import *
import time

ip = IP(src="192.168.1.2", dst="192.168.1.1")
tcp = TCP(sport=3333, dport=4444, flags="S")
#ip.show()
#tcp.show()
pkt = ip/tcp
pkt.show()
#send(pkt)


def create_tcp_packet(port):
    return TCP(sport=4444,dport=port,flags="SU")


def create_ip_packet(ip_addr):
    return IP(dst=ip_addr)

def create_udp_packet(port):
    return UDP(dport=port)

ip_packet = create_ip_packet("172.16.106.130")
pkt = ip_packet/create_tcp_packet(5555)
pkt_2 = ip_packet/create_tcp_packet(7777)
pkt_3 = ip_packet/create_tcp_packet(9999)
send(pkt)
time.sleep(1)
send(pkt_2)
time.sleep(1)
send(pkt_3)


#sc = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#sc.connect(("172.16.106.130",4444))
