import requests
import sys
import subprocess
import os
import http.client
from colorama import Fore, Back, Style
import time

def goBack():
    print(Fore.WHITE+"\n[+] SERVER INFORMATION DETECTION COMPLETED"+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do You Want To Test For Server Information Disclosure Again ? ( y/n <or enter for 'n'> ) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            serverInfo() #Going Back to test For server Information Again
        elif reTest=='n' or reTest=='N' or reTest=='':
            while True:
                choice=input(Fore.GREEN+"\n>> Press Q to Quit or ENTER to go back to index : "+Style.RESET_ALL)
                if(choice=='Q' or choice=='q'):
                    sys.exit() #Exit Program
                elif choice=='':
                    print(Fore.BLUE+"[-] Going back to the Index of Medium Level Vulnerability Scanner")
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
        serverInfo()

def serverInfo():
    link=input(Fore.GREEN+"\n>> Enter The URL <http://domain.com> : "+Fore.RESET) #"http://www.quora.com"
    if 'http' not in link:
        link="http://"+link
    print(Fore.MAGENTA+"[] Checking The Correctness of Given URL")
    checklink(link)
    #since the url is correct:
    print(Fore.BLUE+"[] The Given URL is correct")
    print("[] Sending url request")
    r = requests.get(link) #sendind the given link request
    print("[] Fetching Response Headers")
    headers=r.headers #return 'CaseInsensitiveDict' i.e dictionary object of the given url response header
    if 'server' in headers: #checking for 'server' key in gheader
        serverName=r.headers['server']
        print(Fore.YELLOW+"\n[] The server name is visible, which is : ",serverName)
        print(Fore.YELLOW+"[!!] It might contain a vulnerability that can be exploited! Hiding it is a good practice.")
    else:
        print(Fore.MAGENTA+"\n[..] Server name is not displayed")
    goBack()
