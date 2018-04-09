import os
import json
import shlex
import getpass
import firewall
from colorama import Fore, Style
from netfilterqueue import NetfilterQueue

# def show_statistics(database_filename):
#     with open(database_filename, 'r', os.O_NONBLOCK) as fin:
#         data = json.load(fin)
#         for rule in data["rules"]:
            


def getinput(database_filename = "database.json"):
    rule = shlex.split(input("%s:~/# "%(getpass.getuser())))
    if len(rule) == 0:
        return
    action = rule[0]
    f = firewall.Firewall()

    protocol, sourceip, sport1, sport2, dport1, dport2, action = "all", "any", None, None, None, None, "ACCEPT"

    if "-p" in rule:
        index = rule.index("-p")
        if f.is_protocol_supported(rule[index+1]):
            protocol = rule[index+1]
        else:
            print("ERROR :: Protocol `%s` not supported." %(rule[index+1]))
            return

    if "-s" in rule:
        index = rule.index("-s")
        if f.is_valid_IP_range(rule[index+1]):
            sourceip = rule[index+1]
        else:
            print("ERROR :: Source IP `%s` is incorrect." %(rule[index+1]))
            return

    if "--dport" in rule:
        index = rule.index("--dport")
        valid = f.is_valid_port_range(rule[index+1])
        if valid == 2:
            dport1 = int(rule[index+1][:rule[index+1].index(":")])
            dport2 = int(rule[index+1][rule[index+1].index(":") + 1:])
        elif valid == 1:
            dport1 = int(rule[index+1])
            dport2 = dport1      
        else:
            print("ERROR :: Destination Port `%s` is incorrect." %(rule[index+1]))
            return

    if "--sport" in rule:
        index = rule.index("--sport")
        valid = f.is_valid_port_range(rule[index+1])
        if valid == 2:
            sport1 = int(rule[index+1][:rule[index+1].index(":")])
            sport2 = int(rule[index+1][rule[index+1].index(":") + 1:])
        elif valid == 1:
            sport1 = int(rule[index+1])
            sport2 = sport1      
        else:
            print("ERROR :: Source Port `%s` is incorrect." %(rule[index+1]))
            return

    if "-j" in rule:
        index = rule.index("-j")
        if f.is_action_supported(rule[index+1].upper()):
            action = rule[index+1].upper()
        else:
            print("ERROR :: Action `%s` is not supported." %(rule[index+1]))
            return

    rule = {"protocol" : protocol, "sourceip" : sourceip, "sport1" : sport1, "sport2" : sport2, "dport1" : dport1, "dport2" : dport2, "action" : action}
    open(database_filename, 'a',os.O_NONBLOCK )
    with open(database_filename, 'r', os.O_NONBLOCK) as fin:
        if os.stat(database_filename).st_size:
            data = json.load(fin)
            if data:
                if "-I" in rule:
                    pos = rule[rule.index("-I")+1]
                    if f.is_valid_int(pos):
                        data["rules"].insert(int(pos), rule)
                    else:
                        data["rules"].insert(0, rule)
                else:
                    data["rules"].append(rule)
            else:
                data = { "rules" : [rule]}
            fin.close()
        else:
            data = { "rules" : [rule]}          
        with open(database_filename, 'w', os.O_NONBLOCK) as fout:
            json.dump(data, fout)
            fout.close()

print("\n\n")
while True:
    getinput()

