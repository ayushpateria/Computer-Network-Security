import os
import json
import shlex
import getpass
import firewall
from colorama import Fore, Style
from netfilterqueue import NetfilterQueue

global database_filename

def commit(payload, action,):
    if action == "ACCEPT":
        print(Fore.GREEN + "RESULT :: PACKET ACCEPTED" + Style.RESET_ALL)
        payload.accept()
    else:
        print(Fore.RED + "RESULT :: PACKET DROPPED" + Style.RESET_ALL)
        payload.drop()

def cb(payload):
    global database_filename
    packet = payload.get_payload()
    f = firewall.Firewall()

    with open(database_filename, 'r', os.O_NONBLOCK) as fin:
        data = json.load(fin)
        for rule in data["rules"]:
            if f.handle_packet(packet, rule):
                commit(payload, rule["action"])
                return
        commit(payload, "DROP")


def main(queue_num):
    global database_filename
    database_filename =  "database.json"
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, cb)
    print("Started Firewall .... ")
    nfqueue.run()
    nfqueue.unbind()

main(1)
