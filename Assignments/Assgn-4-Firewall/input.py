import os
import json
import shlex
import getpass
import firewall
from colorama import Fore, Style
from netfilterqueue import NetfilterQueue

def is_valid_int(st):
    try:
        int(st)
        return True
    except ValueError:
        return False

def help():
    print("""\n
optional arguments:
  -p Protocol                   icmp/tcp/udp (default: any)
  -s IP_or_CIDR                 source IP ==> CIDR or complete IP (default: any)
  -sport Port_or_Port:Port      source port ==> individual or range (default: any)
  -dport Port_or_Port:Port      destination port ==> individual or range (default: any)
  -j Target                     ACCEPT/DROP (default: ACCEPT)

usage:  ADD  [-A] [-I Rule_Number] [-p Protocol] [-s IP/CIDR] [-sport Port/Port:Port]
            [-dport Port/Port:Port] [-j Target]
        
        UPDATE [-I Rule_Number] [-p Protocol] [-s IP/CIDR] [-sport Port/Port:Port]
            [-dport Port/Port:Port] [-j Target]

        DELETE all/Rule_Number

        SHOW

        HELP
        \n""")

def showStatistics(database_filename):
    print("Chain INPUT (policy DROP)")
    print("{0: <7}\t{1: <6}\t{2: <4}\t{3: <18}\t".format('Rule-No','target','prot', 'Source-IP'))
    with open(database_filename, 'r', os.O_NONBLOCK) as fin:
        data = json.load(fin)
        for index,rule in enumerate(data["rules"]):
            print("{0: <7}\t{1: <6}\t{2: <4}\t{3: <18}\t".format(index,rule["action"],rule["protocol"], rule["sourceip"]), end='')
            if rule["sport1"]:
                if rule["sport1"] == rule["sport2"]:
                    print('spt {}  '.format(rule["sport1"]), end='')
                else:
                    print('spt {}:{}  '.format(rule["sport1"],rule["sport2"]), end='')
            if rule["dport1"]:
                if rule["dport1"] == rule["dport2"]:
                    print('dpt {}  '.format(rule["dport1"]), end='')
                else:
                    print('dpt {}:{}  '.format(rule["dport1"],rule["dport2"]), end='')
            print('')

def deleteRule(database_filename, rule):
    with open(database_filename, 'r', os.O_NONBLOCK) as fin:
        data = json.load(fin)
        if rule == None:
            data["rules"] = []
        else:
            if rule < 0 or rule >= len(data["rules"]):
                print("Rule with Rule-no {} not found".format(rule))
                return
            data["rules"].pop(rule)
        with open(database_filename, 'w', os.O_NONBLOCK) as fout:
            json.dump(data, fout)
            fout.close()
            print(Fore.GREEN + "\tUPDATED RULE "+ Style.RESET_ALL)
        fin.close()

def getParams(rule):
    f = firewall.Firewall()
    protocol, sourceip, sport1, sport2, dport1, dport2, action = "all", "any", None, None, None, None, "ACCEPT"

    if "-p" in rule:
        index = rule.index("-p")
        if f.is_protocol_supported(rule[index+1]):
            protocol = rule[index+1].lower()
        else:
            print("ERROR :: Protocol `%s` not supported." %(rule[index+1]))
            return None

    if "-s" in rule:
        index = rule.index("-s")
        if f.is_valid_IP_range(rule[index+1]):
            sourceip = rule[index+1]
        else:
            print("ERROR :: Source IP `%s` is incorrect." %(rule[index+1]))
            return None

    if "-dport" in rule:
        if protocol ==  "icmp":
            print("ERROR :: Destination Port cannot be used with ICMP")
            return None

        index = rule.index("-dport")
        valid = f.is_valid_port_range(rule[index+1])
        if valid == 2:
            dport1 = int(rule[index+1][:rule[index+1].index(":")])
            dport2 = int(rule[index+1][rule[index+1].index(":") + 1:])
        elif valid == 1:
            dport1 = int(rule[index+1])
            dport2 = dport1      
        else:
            print("ERROR :: Destination Port `%s` is incorrect." %(rule[index+1]))
            return None

    if "-sport" in rule:
        if protocol ==  "icmp":
            print("ERROR :: Source Port cannot be used with ICMP")
            return None

        index = rule.index("-sport")
        valid = f.is_valid_port_range(rule[index+1])
        if valid == 2:
            sport1 = int(rule[index+1][:rule[index+1].index(":")])
            sport2 = int(rule[index+1][rule[index+1].index(":") + 1:])
        elif valid == 1:
            sport1 = int(rule[index+1])
            sport2 = sport1      
        else:
            print("ERROR :: Source Port `%s` is incorrect." %(rule[index+1]))
            return None

    if "-j" in rule:
        index = rule.index("-j")
        if f.is_action_supported(rule[index+1].upper()):
            action = rule[index+1].upper()
        else:
            print("ERROR :: Action `%s` is not supported." %(rule[index+1]))
            return None
    return {"protocol":protocol,"sourceip":sourceip,"sport1":sport1,"sport2":sport2,"dport1":dport1,"dport2":dport2,"action":action}

def setRule(database_filename, rule, newRule, isUpdate = False):
    open(database_filename, 'a',os.O_NONBLOCK )    
    with open(database_filename, 'r', os.O_NONBLOCK) as fin:
        data = json.load(fin)
        if data:
            if "-I" in rule:
                pos = rule[rule.index("-I")+1]
                if not is_valid_int(pos):
                    print("ERROR :: -I rule incorrect index")
                    return

                pos = int(pos)
                if pos < 0 or pos >= len(data["rules"]):
                    print("ERROR :: out of range for Rule Number")
                    return
                
                if isUpdate:
                    data["rules"][pos] = newRule
                else:    
                    data["rules"].insert(pos, newRule)
            else:
                data["rules"].append(newRule)
        else:
            data = { "rules" : [newRule]}
        fin.close()
        with open(database_filename, 'w', os.O_NONBLOCK) as fout:
            json.dump(data, fout)
            fout.close()
            print(Fore.GREEN + "\tUPDATED RULE "+ Style.RESET_ALL)

def getInput(database_filename = "database.json"):
    print(Fore.GREEN + "%s:~/# "%(getpass.getuser()) + Style.RESET_ALL, end='')
    rule = shlex.split(input())
    if len(rule) == 0:
      print("ERROR :: No input")
    else:
        action = rule[0].lower()
        if action == "help":
            help()
        elif action == "show":
            showStatistics(database_filename)
        elif action == "delete":
            if len(rule) == 2:
                if(rule[1].lower() == "all"):
                    deleteRule(database_filename, None)
                elif not is_valid_int(rule[1]):
                    print("ERROR :: Incorrect input")
                else:
                    deleteRule(database_filename, (int)(rule[1]))
            else:
                print("ERROR :: Incorrect input")
        elif action == "update":
            if "-A" in rule:
                print("ERROR :: Incorrect input. cannot append")
            elif not "-I" in rule:
                print("ERROR :: Incorrect input. -I not present")
            else:
                newRule = getParams(rule)
                if newRule:
                    setRule(database_filename, rule, newRule, True)
        elif action == "add":
            newRule = getParams(rule)
            if newRule:
                setRule(database_filename, rule, newRule)
        else:
            print("ERROR :: Incorrect action")

help()
while True:
    getInput()

