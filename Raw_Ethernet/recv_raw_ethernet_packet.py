import argparse
import socket
import struct
import sys
import select
import json
import os
import selectors

from misc_raw_ethernet import *
from get_protocols import get_protocols_list


def get_protocol_name(protocol_list, coming_data):
    if len(coming_data) != 6:
        coming_data = coming_data[:2] + (6 - len(coming_data)) * '0' + coming_data[2:]
    for i in protocol_list:
        if i["value"] == coming_data:
            return i["exp"]
    return None


if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--iface', required=True, dest="interface_name_var", type=check_interface_is_exist)
    parsed_arg = argparser.parse_args()
    interface = vars(parsed_arg)['interface_name_var']

    if not os.path.exists("procol_eth.json"):
        get_protocols_list()

    f = open("protocol_eth.json")
    protocols_data = json.load(f)

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except socket.error as err:
        print(err)
        sys.exit(-1)

    s.bind((interface, 0))
    """
    with selectors.DefaultSelector() as selector:
        #register the socket for reading
        #when socket is readable , select() function return the socket
        selector.register(s.file_no(),selectors.EVENT_READ)
        while True:
            #if registered socket is readable , then return 
            ready_socket = selector.select()
            if ready_socket:
                frame = sock.recv(ETH_FRAME_LEN)
                print(frame)
                header = frame[:ETH_HLEN]
                dest, src, proto = struct.unpack('!6s6sH', header)
                # rest of the bytes are payload
                payload = frame[ETH_HLEN:]
    """

    selectors.EVENT_READ
    read_list = [s]
    while True:
        readable, _, _ = select.select(read_list, [], [])
        for sock in readable:
            # GET FRAME
            frame = sock.recv(ETH_FRAME_LEN)
            # get header from frame 6 bytes
            """
                6 bytes => dest mac address
                6 bytes => src mac address
                2 bytes => protocol type
                ETH_HLEN => 6 + 6 + 2 => 14 bytes
                thus , we do like that [:ETH_HLEN]
                means frame header length => 14 byte
            """
            print(frame)
            header = frame[:ETH_HLEN]
            dest, src, proto = struct.unpack('!6s6sH', header)
            # rest of the bytes are payload
            payload = frame[ETH_HLEN:]

            print(f"src: {convert_byte_to_str_mac_address(src)}\n"
                  f"dest: {convert_byte_to_str_mac_address(dest)}\n"
                  f"type:{hex(proto)} : {get_protocol_name(protocols_data,hex(proto))}\n"
                  f"payload:{payload[:4]}\n")

    s.close()
