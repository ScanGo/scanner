import sys
import subprocess
import os
import http.client
from colorama import Fore, Back, Style
import time

def goBack():
    print(Fore.WHITE+"\n[+] Checked for DNS Zone Transfer Misconfiguartion "+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do You Want To Check For DNS Misconfiguartion Again? (y/N) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            dnsMisconf() #Calling funacitob to detect for DNS Misconfiguartion again
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
        dnsMisconf()

def dnsMisconf():
    check=1
    domain=input(Fore.GREEN+"\n>> Enter the domain name <domain.com> : "+Fore.RESET)
    checkDomain(domain)
    print(Fore.WHITE+"[] Valid Domain entered")
    print(Fore.BLUE+"\n[] Checking for ns records! ..\n\n"+Style.RESET_ALL)
    lookup=subprocess.check_output(['nslookup','-type=ns',domain])
    nsRecord=[]
    #print(print(Fore.BLUE+"[] Processing the resultant data"+Style.RESET_ALL))
    cmd_data=str(lookup).split("\\n")
    for line in cmd_data:
        if "nameserver" in line:
            data=str(line).split(" ")
            nameserver=data[2]
            nsRecord.append(nameserver)
    print(Fore.RED,len(nsRecord),Fore.WHITE+" Records Found ->",Fore.GREEN,end=' ')
    print(' ; '.join(str(nsrecord) for nsrecord in nsRecord))
    for nsData in nsRecord :
        nsData="@"+nsData
        data=subprocess.check_output(['dig','axfr',nsData,domain])
        #data.decode("utf-8"))
        data=str(data).split("\\n")
        Tdata=data[4:]
        try :
            if "Transfer failed." in Tdata[0]:
                continue
            else :
                check=0
                Tdata=Tdata[0:-6]
                print("\n\n"+Fore.YELLOW+"*"*40+" RECORDS FOUND! "+"*"*40)
            for rec in Tdata:
                inData=str(rec).split("\\t")
                print(Fore.RED+"# ",end=''+Fore.WHITE)
                for r in inData:
                    print('{:<5s}'.format(r),end=" | ")
                print("\n")
            break
        except Exception:
            check=1
    if check==1:
        print(Fore.YELLOW+"\n\n[@][@] DNS Zone Transfer Vulnerability not detected!")
    else :
        print(Fore.RED+"\n\n[@][!] DNS Zone Transfer Successful")
    goBack()
#https://wiki.sep.de/wiki/index.php/How_to_check_DNS_configuration#Tools_to_check_DNS_resolution
#https://www.cybrary.it/0p3n/find-dns-zone-transfer-misconfiguration/
#https://digi.ninja/projects/zonetransferme.php
#https://hsploit.com/dns-zone-transfer-tutorial/
