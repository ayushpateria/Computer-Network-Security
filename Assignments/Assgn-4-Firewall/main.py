import os
import time
import json
import shlex
import getpass
import firewall
from colorama import Fore, Style
from netfilterqueue import NetfilterQueue

global database_filename, total_packets, packet_accepted

def commit(payload, action,):
    global packet_accepted

    if action == "ACCEPT":
        print(Fore.GREEN + "RESULT :: PACKET ACCEPTED" + Style.RESET_ALL)
        payload.accept()
        packet_accepted += 1
    else:
        print(Fore.RED + "RESULT :: PACKET DROPPED" + Style.RESET_ALL)
        payload.drop()

def cb(payload):
    global database_filename, total_packets
    
    packet = payload.get_payload()
    f = firewall.Firewall()
    total_packets += 1
    ruleNumber = -1

    with open(database_filename, 'r', os.O_NONBLOCK) as fin:
        data = json.load(fin)
        for index, rule in enumerate(data["rules"]):
            if f.handle_packet(packet, rule):
                ruleNumber = index
                commit(payload, rule["action"])
                break

    if ruleNumber < 0:
        commit(payload, "DROP")

    timestamp = time.time()

    with open("log.txt", 'a', os.O_NONBLOCK) as fout:
        fout.write("{} {}\n".format(timestamp, ruleNumber))


def main(queue_num):
    global database_filename, total_packets, packet_accepted
    database_filename =  "database.json"
    total_packets = 0
    packet_accepted = 0
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, cb)
    print("Started Firewall .... ")
    
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("Keyboard Interrupt")

    nfqueue.unbind()
    print("Queue Closed\n")
    print("STATISTICS\n\tTotal Packets :: {}\n\tPackets Accepted :: {}\n\tPackets Dropped :: {}".format(total_packets, packet_accepted, total_packets - packet_accepted))

main(1)
