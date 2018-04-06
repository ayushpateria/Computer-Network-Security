#Program to build a mini firewall using python

import sys
import time
import math
import struct
import socket
from netfilterqueue import NetfilterQueue
from socket import inet_ntoa

global action, inputprotocol, actiontype, inputportnum, inputipaddr

class Firewall:
    def __init__(self):
        self.protocolname = ''
        self.srcipaddress = ''
        self.srcportnum = 0

    # Since struct unpack gives a tuple as result, this function removes unnecessary characters (,) and returns the number
    def strip_format(self, format_str):
        new_str = str(format_str)
        return int(new_str[1: len(new_str) - 2])
    
    def get_packet_directionection(self, direction):
        if (direction == 'outgoing'):
            return 'outgoing'
        else:
            return 'incoming'
    # functions for protocols
    def get_protocol(self, protocol):
        if (protocol == 1):
            return "icmp"
        elif (protocol == 6):
            return 'tcp'
        elif (protocol == 17):
            return 'udp'
        else:
            return None

    def is_protocol_supported(self, protocol):
        return (protocol == 'tcp') or (protocol == 'udp') or (protocol == 'icmp')

    def get_protocol_packet_length(self, packet):
        try:
            protocol = struct.unpack('!B', packet[9:10])
            total_length = struct.unpack('!H', packet[2:4])
            return self.strip_format(protocol), self.strip_format(total_length)
        except struct.error as e:
            print(e)
            return None, None

    # functions for port
    def get_port(self, packet, startIndex):
        try:
            port = packet[startIndex: startIndex + 2]
            port = struct.unpack('!H', port)
            return port
        except struct.error:
            return None

    def is_port_in_range(self, port , start_port, end_port = None):
        if (end_port):
            return port >= start_port and port <= end_port
        else:
            return port == start_port

    # functions for IP address
    def get_ip_header_length(self, packet):
        try:
            ip_header_length = struct.unpack('!B', packet[0:1])
            return self.strip_format(ip_header_length)
        except struct.error as e:
            print(e)
            print(packet[0:1])
            return None

    def is_valid_IP_address(self, ext_addr):
        try:
           socket.inet_ntoa(ext_addr)
           return True
        except socket.error:
           return False

    def get_IP_address(self, data, netmask = None):
        data = ''.join(data.split("."))
        if(netmask):
            ip = int(data)
            bitmask = math.pow(2,32 - netmask) * (math.pow(2,netmask) - 1)
            return (ip & bitmask) >> (32 - netmask)
        else
            return int(data)

    def get_IP_netmask(self, data):
        if (data.find('/')):
            return data[0:data.find("/")], int(data[data.find("/")+1])
        else:
            return data, None

    def is_valid_IP_range(self, data):
        if (data.find('/')):
            netmask = data[data.find("/")+1]
            try:
                inetmask = int(netmask)
                if(inetmask < 0):
                    print("PACKET ERROR :: Invalid netmask `",netmask,"` specified")
                    return False
                return self.is_valid_IP_address(data[0:data.find("/")])
            except ValueError:
                print("PACKET ERROR :: Invalid netmask `",netmask,"` specified")
                return False
        else:
            return self.is_valid_IP_address(data)

    def is_IP_in_range(self, ip, allowed_ip):
        allowed_ip, netmask = self.get_IP_netmask(allowed_ip)
        if netmask == 0:
            return True
        elif(netmask == None):
            if (ip == allowed_ip):
                return True
            else:
                return False
        elif(self.get_IP_address(allowed_ip, netmask) == self.get_IP_address(ip, netmask)):
            return True
        else:
            return False


    # functions for ICMP   
    def handle_icmp_packet(self, packet, startIndex):
        try:
            type_field = packet[startIndex: startIndex + 1]
            type_field = struct.unpack('!B', type_field)
            return self.strip_format(type_field)
        except struct.error:
            return None

    #functions for UDP
    def get_udp_length(self, packet, startIndex):
        try:
            length = struct.unpack('!H', packet[startIndex + 4 : startIndex + 6])
            return self.strip_format(length)
        except struct.error:
            return None

    def handle_packet(self, packet_direction, packet):
        #network packets are big-endian 
        ip_header = self.get_ip_header_length(packet)

        if (ip_header == None):
            print("PACKET ERROR :: Invalid ip_header")
            return False

        ip_header = ip_header & 0x0f    #get last 4 bits - header_length
        if (ip_header < 5):        #minimum value of correct header length is 5
            print("PACKET ERROR :: Header length should be >= 5")
            return False
        
        protocol, total_length = self.get_protocol_packet_length(packet)
        if (protocol == None || total_length == None):
            print("PACKET ERROR :: Cannot Determine protocol/total_length from packet")
            return False

        if (total_length != len(packet)):
            print("PACKET ERROR :: Bytes missing from packet")
            return False

        if (self.get_protocol(protocol) == None):
            print("PACKET ERROR :: Protocol not supported")
            return False

        src_addr, dst_addr, packet_direction = packet[12:16], packet[16:20], self.get_packet_directionection(packet_direction)
        if (packet_direction == 'incoming'):
            external_addr = src_addr
        else:
            external_addr = dst_addr
        if not (self.is_valid_IP_address(external_addr)): # check valid address.
            print(6)
            return

        if (protocol == 6): # TCP
            if (packet_direction == 'incoming'):
                external_port = self.handle_external_port(packet, (ip_header) * 4)
            else:
                external_port = self.handle_external_port(packet, ((ip_header) * 4) + 2)
            if (external_port == None): # drop packet due to port socket error.
                print(7)
                return

        elif (protocol == 1): # ICMP
            type_field = self.handle_icmp_packet(packet, (ip_header * 4))
            if (type_field == None):
                print(8)
                return

        elif (protocol == 17): # UDP
            udp_length = self.get_udp_length(packet, (ip_header * 4))
            if (udp_length == None or udp_length < 8):
                #minimum UDP length : 8
                print(9)
                return
            if (packet_direction == 'incoming'):
                external_port = self.handle_external_port(packet, (ip_header) * 4)
                if (external_port == None):
                    print(10)
                    return

        verdict = "pass"
        self.protocolname = self.get_protocol(protocol)
        self.srcipaddress = external_addr
        if (protocol != 1):
            self.srcportnum = external_port


def cb(payload):
    print("received packet len :: ", payload.get_payload_len())

    data = payload.get_payload()
    f = Firewall()
    f.handle_packet("incoming", data)
    print('*************************')
    print(f.protocolname)
    print(socket.inet_ntoa(f.srcipaddress))
    print(f.srcportnum)

    if action == "block":
        if actiontype == "protocol":

            if inputprotocol == f.protocolname:  #TCP, UDP, ICMP
                payload.drop()
                print(f.protocolname + " Packet blocked")

        elif actiontype == "ipaddress":

            if inputipaddr == socket.inet_ntoa(f.srcipaddress):  #IP address
                payload.drop()
                print(socket.inet_ntoa(f.srcipaddress) + " blocked")

        elif actiontype == "portnum":
            if int(inputportnum) in f.srcportnum:
                payload.drop()
                print(inputportnum + " blocked")

    elif action == "accept":
        payload.accept()
        print("Packet accepted")

    else:
        payload.accept()
        print("Packet accepted")

def main(queue_num):
    global action, inputprotocol, actiontype, inputportnum, inputipaddr

    actiontype = "ipaddress"
    action = "block"
    inputportnum = 20
    inputipaddr=  "202.137.235.12"
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, cb)
    print("starting listening")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("Interrupted")

    print("unbind")
    nfqueue.unbind()

main(1)
