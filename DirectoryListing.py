import requests
import sys
import re
import subprocess
import os
import http.client
from colorama import Fore, Back, Style
import time
from pprint import pprint

def goBack():
    print(Fore.WHITE+"\n[+] CHECK FOR DIRECTORY LISTING COMPLETED"+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do You Want To Test For Directory Listing Again ? (y/N) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            directoryListing() #Going Back to test For HTTP Header Information Again
        elif reTest=='n' or reTest=='N' or reTest=='':
            while True:
                choice=input(Fore.GREEN+"\n>> Press Q to Quit or ENTER to go back to index : "+Style.RESET_ALL)
                if(choice=='Q' or choice=='q'):
                    sys.exit() #Exit Program
                elif choice=='':
                    print(Fore.BLUE+"[-] Going back to the Index of Informative Level Vulnerability Scanner")
                    return
                else:
                    print(Fore.RED+Style.DIM+"[X] Invalid choice, enter Again : "+Style.RESET_ALL)
        else :
            print(Fore.RED+Style.DIM+"[X] Invalid choice, Enter Again : "+Style.RESET_ALL)
            
def checklink(link):
    #To check the correctness of link
    try:
        r=requests.get(link)
    except Exception:
        print(Fore.RED+Style.DIM+"[X] Wrong Link Given, Try Again."+Style.RESET_ALL)
        directoryListing()

def directoryListing():
    check=0
    domain=input(Fore.GREEN+"\n>> Enter The domain <domain.com> : "+Fore.RESET) #"http://www.quora.com"
    if 'https' not in domain:
        link="https://"+domain
    print(Fore.MAGENTA+"[] Checking The Correctness of Given URL")
    checklink(link)
    #since the url is correct:
    print(Fore.BLUE+"[] The Given Domain is Valid")
    print("\n[]Fetching Potential Directory of the given domain")
    nmap=subprocess.check_output(['wget','--spider','-r','--no-parent',domain],stderr=subprocess.STDOUT)
    print("\n[]Processinf the result data")
    folderData=subprocess.check_output(['ls'],stderr=subprocess.STDOUT)
    cmd_data=str(folderData).split("\\n")
    if domain in cmd_data:
        print(Fore.WHITE+"[] Successfully gathered Directory result")
        domain=domain+'/'
        checkInside=subprocess.check_output(['ls',domain],stderr=subprocess.STDOUT)
        if checkInside == b'':
            print(Fore.YELLOW+"\n\n[] Congratulations! Your server has disabled directory browsing\n\n\n")
        else:
            print(Fore.RED+"\n\n[!] Your server may not have disabled directory browsing\n\n\n")
    else:
        print(Fore.RED+"\n\n[!] Unable to fetch directory result\n\n\n")
    deleteFile=subprocess.check_output(['rm','-rf',domain],stderr=subprocess.STDOUT)
    goBack()
#directoryListing()
#wget --spider -r --no-parent http://some.served.dir.ca/

