import sys
import subprocess
import os
import http.client
from colorama import Fore, Back, Style
import time

def goBack():
    print(Fore.WHITE+"\n[+] Open Ports Successfully Detected "+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do You Want To Check For Open Ports Again? ( y/N ) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            openPortDetection() #Calling funacitob to detect for open Ports again
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

def openPortDetection():
    line="-"*40
    domain=input(Fore.GREEN+"\n>> Enter the domain name <domain.com> : "+Fore.RESET)
    checkDomain(domain)
    print(Fore.BLUE+"[] Domain name is valid"+Style.RESET_ALL)
    #os.system("nmap -T4 -sT "+domain) to get command result in realtime
    print(Fore.BLUE+"\n[] Fetching data to detect for Open Ports"+Style.RESET_ALL)
    nmap=subprocess.check_output(['nmap','-T4','-sT',domain]) #store nmap data to check for open ports in variable
    #print(print(Fore.BLUE+"[] Processing the resultant data"+Style.RESET_ALL))
    cmd_data=str(nmap).split("\\n")
    print(line)
    print(Fore.YELLOW+'{:<5s}{:>0s}{:>10s}{:>10s}'.format(" ","POST","STATE","SERVICE")+Style.RESET_ALL)
    print(line)
    for data in cmd_data :
        if "open" in data :
            print('{:<5s}{:<30s}{:>5s}'.format("|",data,"|")) #print data if open
    print(line)
    goBack()
