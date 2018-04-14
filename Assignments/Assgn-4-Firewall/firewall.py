#Program to build a mini firewall using python
import math
import socket
import struct
import time
import psutil
from IPy import IP
from colorama import Fore, Style
from cli import *

class Firewall:
    def __init__(self):
        self.scanLog = []

    # functions for port
    def get_port(self, packet, startIndex):
        try:
            port = packet[startIndex: startIndex + 2]
            port = struct.unpack('!H', port)
            return strip_format(port)
        except struct.error:
            return None         


    def is_port_in_range(self, port , start_port, end_port):
        return port >= start_port and port <= end_port

    # functions for IP address
    def get_ip_header_length(self, packet):
        try:
            ip_header_length = struct.unpack('!B', packet[0:1])
            return strip_format(ip_header_length)
        except struct.error as e:
            print(e)
            print(packet[0:1])
            return None

    def is_valid_IP_address(self, ext_addr):
        if isinstance(ext_addr, str):
            try:
                IP(ext_addr)
                return True
            except ValueError:
                return False
        else:
            try:
               socket.inet_ntoa(ext_addr)
               return True
            except socket.error:
               return False

    def get_IP_address(self, data, netmask = None):
        data = ''.join(data.split("."))
        if netmask:
            ip = int(data)
            bitmask = math.pow(2,32 - netmask) * (math.pow(2,netmask) - 1)
            return (ip & bitmask) >> (32 - netmask)
        else:
            return int(data)

    def get_IP_netmask(self, data):
        if "/" in data:
            return data[0:data.find("/")], int(data[data.find("/")+1])
        else:
            return data, None

    # Since struct unpack gives a tuple as result, this function removes unnecessary characters (,) and returns the number
    def strip_format(self, format_str):
        new_str = str(format_str)
        return int(new_str[1: len(new_str) - 2])

    def get_protocol(self, protocol):
        if (protocol == 1):
            return "icmp"
        elif (protocol == 6):
            return 'tcp'
        elif (protocol == 17):
            return 'udp'
        else:
            return None

    def get_protocol_packet_length(self, packet):
        try:
            protocol = struct.unpack('!B', packet[9:10])
            total_length = struct.unpack('!H', packet[2:4])
            return self.strip_format(protocol), self.strip_format(total_length)
        except struct.error as e:
            print(e)
            return None, None

    def is_IP_in_range(self, ip, allowed_ip):
        allowed_ip, netmask = self.get_IP_netmask(allowed_ip)
        if netmask == 0:
            return True
        elif netmask == None:
            if (ip == allowed_ip):
                return True
            else:
                return False
        elif self.get_IP_address(allowed_ip, netmask) == self.get_IP_address(ip, netmask):
            return True
        else:
            return False


    # functions for ICMP   
    def get_icmp_packet(self, packet, startIndex):
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

    # check_port_scan works by keeping the record of invalid port requested by each IP in last seconds in memory.
    def check_port_scan(self, srcip, port):
       
        portsAvail = []
        for x in psutil.net_connections("all"):
            if hasattr(x.laddr, 'port'):
                portsAvail.append(x.laddr.port)
        invalidPort = False
        print(portsAvail, port)
        if port not in portsAvail:
            invalidPort = True
        else:
            return True
        invalidCount = 1
        ts = int(time.time() / 60)
        newLog = []
        updated = False
        for i, record in enumerate(self.scanLog):
            if record[0] == ts:
                print(srcip)
                if record[1] == srcip:
                    # Increment the count for invalid ports
                    record[2] += 1
                    invalidCount = record[2]
                    updated = True
                newLog.append(record)
        if not updated:
            newLog.append([ts, srcip, 1])
        
        self.scanLog = newLog
        print(self.scanLog)
        if invalidCount > 5:
            print("Port scan detected, blocking ", srcip)
            rule = "ADD -i 0 -s " + str(srcip) + " -j DROP"
            setRule("database.json", rule, getParams(rule))
            return False
        return True

    def handle_packet(self, packet, rule):
        #network packets are big-endian 
        ip_header = self.get_ip_header_length(packet)

        if (ip_header == None):
            print(Fore.YELLOW + "ERROR :: Invalid ip_header" + Style.RESET_ALL)
            return None

        ip_header = ip_header & 0x0f    #get last 4 bits - header_length
        if (ip_header < 5):        #minimum value of correct header length is 5
            print(Fore.YELLOW + "ERROR :: Header length should be >= 5" + Style.RESET_ALL)
            return None
        
        protocol, total_length = self.get_protocol_packet_length(packet)
        if (protocol == None or total_length == None):
            print(Fore.YELLOW + "ERROR :: Cannot Determine protocol/total_length from packet" + Style.RESET_ALL)
            return None

        if (total_length != len(packet)):
            print(Fore.YELLOW + "ERROR :: Bytes missing from packet" + Style.RESET_ALL)
            return None

        if (self.get_protocol(protocol) == None):
            print(Fore.YELLOW + "ERROR :: Protocol not supported" + Style.RESET_ALL)
            return None

        src_addr, dst_addr = packet[12:16], packet[16:20]
        if not (self.is_valid_IP_address(src_addr) and self.is_valid_IP_address(dst_addr)): # check valid address.
            print(Fore.YELLOW + "ERROR :: IP addresses are incorrect" + Style.RESET_ALL)
            return None

        #UDP validation
        if protocol == 17:
            udp_length = self.get_udp_length(packet, (ip_header * 4))
            if (udp_length == None or udp_length < 8):      #minimum UDP length : 8
                print(Fore.YELLOW + "ERROR :: UDP length should be >= 8" + Style.RESET_ALL)
                return None

        #filter protocol
        if (rule["protocol"] != "all") and (rule["protocol"] != self.get_protocol(protocol)):
            print(Fore.YELLOW + "FILTER :: Protocol not matched" + Style.RESET_ALL)
            return False

        #filter IP addresses
        if rule["sourceip"] != "any":
            if not self.is_IP_in_range(socket.inet_ntoa(src_addr), rule["sourceip"]):
                print(Fore.YELLOW + "FILTER :: IP not in specified range" + Style.RESET_ALL)
                return False

        #filter ports
        if ((protocol == 6) or (protocol == 17)) and ((rule["protocol"] == "all") or (rule["protocol"] == "tcp") or (rule["protocol"] == "udp")):
            if rule["sport1"]:
                port = self.get_port(packet, (ip_header) * 4)
                if port == None:
                    print(Fore.YELLOW + "ERROR :: Source Port is incorrect" + Style.RESET_ALL)
                    return None
                elif not self.is_port_in_range(port, rule["sport1"], rule["sport2"]):
                    print(Fore.YELLOW + "FILTER :: Source Port is not in specified range" + Style.RESET_ALL)
                    return False

            if rule["dport1"]:
                port = self.get_port(packet, ((ip_header) * 4) + 2)
                if port == None:
                    print(Fore.YELLOW + "ERROR :: Source Port is incorrect" + Style.RESET_ALL)
                    return None
                elif not self.is_port_in_range(port, rule["dport1"], rule["dport2"]):
                    print(Fore.YELLOW + "FILTER :: Destination Port is not in specified range" + Style.RESET_ALL)
                    return False

        if (protocol == 1) and ((rule["protocol"] == "all") or (rule["protocol"] == "icmp")): # ICMP
            type_field = self.get_icmp_packet(packet, (ip_header * 4))
            if (type_field == None):
                print(Fore.YELLOW + "ERROR :: ICMP Type is incorrect" + Style.RESET_ALL)
                return None

        # Check for a potential port scan 
        dport = self.get_port(packet, ((ip_header) * 4) + 2)    
        if not self.check_port_scan(src_addr, dport):
            return False
        return True
