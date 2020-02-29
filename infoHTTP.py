import requests
import sys
import subprocess
import os
import http.client
from colorama import Fore, Back, Style
import time

def goBack():
    print(Fore.WHITE+"\n[+] HTTP HEADER INFORMATION DETECTION COMPLETED"+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do You Want To Test For HTTP Header Information Disclosure Again ? (y/N) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            httpInfo() #Going Back to test For HTTP Header Information Again
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
        httpInfo()

def httpInfo():
    check=0
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
    if 'server' in headers: #checking for 'server' key in header
        serverName=r.headers['server']
        print(Fore.YELLOW+"\n[] The server name is visible, which is : ",serverName)
        print(Fore.RED+"[!!] It might be a vulnerability. Hiding it is a good practice.")
        check=check+1
    if 'loaction' in headers: #checking for 'location' key in gheader
        location=r.headers['location']
        print(Fore.YELLOW+"\n[] The location is visible, which is : ",location)
        print(Fore.RED+"[!!] It can be tampered. Hiding it is a good practice.")
        check=check+1
    if 'X-Powered-By​' in headers: #checking for 'X-Powered-By​' key in gheader
        xPow=r.headers['X-Powered-By​']
        print(Fore.YELLOW+"\n[] The X-Powered-By​ is visible, which is : ",xPow)
        print(Fore.RED+"[!!] It might be a vulnerability. Hiding it is a good practice.")
        check=check+1
    if 'X-AspNet-Version​' in headers: #checking for 'X-Powered-By​' key in gheader
        xVer=r.headers['X-AspNet-Version']
        print(Fore.YELLOW+"\n[] The AspNet-Version is visible, which is : ",xVer)
        print(Fore.RED+"[!!] It might be a vulnerability. Hiding it is a good practice.")
        check=check+1
    if check==0:
        print(Fore.RED + " [!] No Important Information is disclosed over HTTP")
    #print(Fore.YELLOW + "\n\n\n@@@ REST OF THE HEADERS GORANG WILL TELL TO INCLUDE @@@")
    goBack()

#https://blogs.msdn.microsoft.com/varunm/2013/04/23/remove-unwanted-http-response-headers/
