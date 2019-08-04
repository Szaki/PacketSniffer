#!/usr/bin/python3

import socket
import struct
import datetime
import os
from collections import namedtuple

PacketAddr = namedtuple('PacketAddr', 'src dest')
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
log = {}

def get_packet_addr(packet):
    eth_data = struct.unpack("!6s6sH", packet[:14])
    if socket.ntohs(eth_data[2]) == 8:
        ip_data = struct.unpack("!BBHHHBBH4s4s", packet[14:34])
        return PacketAddr(socket.inet_ntoa(ip_data[8]), socket.inet_ntoa(ip_data[9]))
    else:
        return None

def get_time():
    date = str(datetime.datetime.now()).split(' ')
    return date[0], date[1][:5]

def log_packet_addr(packetaddr):
    if log.get(packetaddr.src) is None:
        log[packetaddr.src] = [1,0]
    else:
        log[packetaddr.src][0] += 1
    if log.get(packetaddr.dest) is None:
        log[packetaddr.dest] = [0,1]
    else:
        log[packetaddr.dest][1] += 1

def check_file(filename):
    if not os.path.exists(filename):
        with open(filename, "w") as f:
            f.write("Time,IP Address,Incoming,Outgoing,Total\n")

def sort_log():
    log_list = [(key, val[0], val[1], val[0]+val[1]) for key, val in log.items()]
    log_list.sort(key = lambda n: n[3], reverse = True)
    log.clear()
    return log_list

def main():
    currday, currtime = get_time()
    while True:
        packetaddr = get_packet_addr(s.recvfrom(65565)[0])
        if packetaddr is None:
            continue
        log_packet_addr(packetaddr)
        day, time = get_time()
        if day != currday or time != currtime:
            filename = "{}.csv".format(day)
            check_file(filename)
            with open(filename, "a") as f:
                for line in sort_log():
                    f.write(f"{time},{line[0]},{line[2]},{line[1]},{line[3]}\n")
            print(f"Logged traffic by {time}")
            currday = day
            currtime = time

if __name__ == "__main__":
    print("Logging traffic...")
    main()