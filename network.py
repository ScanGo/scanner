import sys
import subprocess
import os
import http.client
from colorama import Fore, Back, Style
import time

def goBack():
    print(Fore.WHITE+"\n[+] Network Enumeration Successfully Completed "+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do You Want perform Network Enumeration Again? ( y/N ) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            networkEnum() #Calling funacitob to detect for open Ports again
        elif reTest=='n' or reTest=='N' or reTest=='':
            while True:
                choice=input(Fore.BLUE+"Press Q to Quit or ENTER to go back to index : "+Style.RESET_ALL)
                if(choice=='Q' or choice=='q'):
                    sys.exit() #Exit Program
                elif choice=='':
                    print(Fore.BLUE+"[-] Going back to the Index of Medium Level Vulnerability Scanner"+Fore.RESET)
                    return
                else:
                    print(Fore.RED+Style.DIM+"[X] Invalid choice, enter Again : "+Style.RESET_ALL)
        else :
            print(Fore.RED+Style.DIM+"[X] Invalid choice, Enter Again : "+Style.RESET_ALL)


def checkDomain(domain):
    print(Fore.MAGENTA+"\n[] Checking the authenticity of domain given"+Style.RESET_ALL)
    try:
        request = http.client.HTTPConnection(domain) #attempt to connect to domain
        request.connect()
        return
    except Exception:
        print(Fore.RED+Style.DIM+"[X] Invalid domain name given. going back to try again \n\n"+Style.RESET_ALL)
        openPortDetection()

def networkEnum():
    line="-"*40
    domain=input(Fore.GREEN+"\n>> Enter the domain name <domain.com> : "+Fore.RESET)
    checkDomain(domain)
    print(Fore.BLUE+"[] Domain name is valid"+Style.RESET_ALL)
    #os.system("nmap -T4 -sT "+domain) to get command result in realtime
    print(Fore.BLUE+"\n[] Starting with Network Enumeration "+Style.RESET_ALL)
    print("\n\n"+line)
    print(Fore.WHITE+"[] WHOIS LOOKUP  []"+Style.RESET_ALL)
    nmap=subprocess.check_output(['whois',domain],stderr=subprocess.STDOUT) #store nmap data to check for open ports in variable
    cmd_data=str(nmap).split("\\n")
    print(line)
    for data in cmd_data:
        if ">>>" not in data:
            print(Fore.YELLOW+data+Style.RESET_ALL)
        else :
            break
    print(line+"\n\n")
    print(line)
    print(Fore.WHITE+"[] DNS LOOKUP  []"+Style.RESET_ALL)
    nmap=subprocess.check_output(['nslookup',domain],stderr=subprocess.STDOUT) #store nmap data to check for open ports in variable
    cmd_data=str(nmap).split("\\n")
    print(line)
    for data in cmd_data:
        print(Fore.YELLOW+data+Style.RESET_ALL)
    print(line)
    goBack()
#networkEnum()
