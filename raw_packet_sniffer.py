import socket
import os

#host ip
HOST = "192.168.8.100"

socket_protocol = socket.IPPROTO_IP

#create socket
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

#bind to interface
sniffer.bind((HOST, 0))

#include ip header
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

#enable promiscuous mode
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

while True:
    # read in a packet
    raw_buffer = sniffer.recvfrom(65565)
    
    print(raw_buffer)

