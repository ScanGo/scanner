import requests
import sys
import subprocess
import os
import http.client
from colorama import Fore, Back, Style
import time

def goBack():
    print(Fore.WHITE+"\n[+] CHECK FOR POSSIBLE HTTP HEADER INJECTION COMPLETED!"+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do You Want To Test For HTTP Header Injection Again ? (y/N) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            httpHeaderInj() #Going Back to test For Header Injection Again
        elif reTest=='n' or reTest=='N' or reTest=='':
            while True:
                choice=input(Fore.GREEN+"\n>> Press Q to Quit or ENTER to go back to index : "+Style.RESET_ALL)
                if(choice=='Q' or choice=='q'):
                    sys.exit() #Exit Program
                elif choice=='' or choice=='b':
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
        httpHeaderInj()

def httpHeaderInj():
    link=input(Fore.GREEN+"\n>> Enter The URL <http://domain.com> : "+Fore.RESET) #"http://www.quora.com"
    if 'http' not in link:
        link="http://"+link
    print(Fore.MAGENTA+"[] Checking The Correctness of Given URL")
    checklink(link)
    #since the url is correct:
    print(Fore.BLUE+"[] The Given URL is correct")
    print("[] Sending url request")
    r = requests.get(link) #sendind the given link request
    print("[] Checking For Important Headers")
    headers=r.headers #return 'CaseInsensitiveDict' i.e dictionary object of the given url response header
    print(Fore.WHITE+"\nOld Header : ",headers)
    addheaders={'unwanted header':'hahaha'}
    #r.headers.update(addheaders)
    print(Fore.CYAN+"\nNew Header : ",addheaders)
    nr = requests.get(link,headers=addheaders)
    newHeaders=nr.headers
    print(Fore.GREEN+"\n[-] -- Requesting page with unwanted header data! --")
    if 'unwanted header' in newHeaders:
        print(Fore.WHITE+"\n\n"+"-"*46)
        print(Fore.RED+"[!!] HTTP Header Injection Attempt Confirmed!")
        print(Fore.WHITE+"-"*46)
    else:
        print(Fore.WHITE+"\n\n"+"-"*46)
        print(Fore.YELLOW+"[!!] HTTP Header Injection Attempt Failed!")
        print(Fore.WHITE+"-"*46)
    goBack()
#https://www.thesslstore.com/blog/http-security-headers/
