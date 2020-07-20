import sys
import subprocess
import os
import http.client
from colorama import Fore, Back, Style
import time

def goBack():
    print(Fore.WHITE+"\n[+] TLS Versions Successfully Detected "+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do You Want To Check For TLS Again? ( y/N ) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            TLScheck() #Calling funacitob to detect for open Ports again
        elif reTest=='n' or reTest=='N' or reTest=='':
            while True:
                choice=input(Fore.BLUE+"Press Q to Quit or ENTER to go back to index : "+Style.RESET_ALL)
                if(choice=='Q' or choice=='q'):
                    sys.exit() #Exit Program
                elif choice=='':
                    print(Fore.BLUE+"[-] Going back to the Index of Informative Level Vulnerability Scanner"+Fore.RESET)
                    return #problem
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
        TLScheck()

def TLScheck():
    check=1
    line="-"*40
    domain=input(Fore.GREEN+"\n>> Enter the domain name <domain.com> : "+Fore.RESET)
    checkDomain(domain)
    print(Fore.BLUE+"[] Domain name is valid"+Style.RESET_ALL)
    #os.system("nmap -T4 -sT "+domain) to get command result in realtime
    print(Fore.BLUE+"\n[] Fetching data to detect the TLS versions for given domain"+Style.RESET_ALL)
    nmap=subprocess.check_output(['nmap','--script','ssl-enum-ciphers','-p','443',domain]) #store nmap data to check for open ports in variable
    print(Fore.BLUE+"[] Processing the resultant data"+Style.RESET_ALL)
    cmd_data=str(nmap).split("\\n")
    #print(cmd_data)
    print(Fore.WHITE+"\n[] Below is the list of TLS or SSL version running by the given domain")
    print(line)
    for data in cmd_data:
        if "TLSv" in data or "SSLv" in data:
            lineData=data.split(' ')
            print(lineData[3].replace(":",''))
            check=0
        else:
            continue
    if check==1:
        print(Fore.RED+"[!] Failed to fetch data")
        print(Fore.WHITE,line)
    else:
        print(Fore.WHITE,line)
    goBack()
#TLScheck()
