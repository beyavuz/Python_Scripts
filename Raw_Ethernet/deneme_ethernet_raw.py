from socket import *


def send_ether(src, dst, type, payload, interface="wlp3s0"):
    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((interface, 0))
    return s.send( (dst + src + type + payload).encode() )


send_ether('28:c2:dd:2f:a6:e1', '60:a4:d0:f9:10:07', '0x0800', 'asd')
