import requests
import sys
import subprocess
import os
import http.client
from colorama import Fore, Back, Style
import time
#https://vuldb.com/?id.6805
def goBack():
    print(Fore.WHITE+"\n[+] IMPORTANT HEADER DETECTION COMPLETED"+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do You Want To Test For Header Information Again ? (y/N) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            impHeaderInfo() #Going Back to test For Header Information Again
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
        impHeaderInfo()

def impHeaderInfo():
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
    
    ########### HTTP Strict Transport Security (HSTS) ###########
    print(Fore.YELLOW+"\n[@] HTTP Strict Transport Security (HSTS) : ",end = ' ')
    if 'strict-transport-security' in headers: #checking for 'Strict-Transport-Security' key in gheader
        hstsInfo=r.headers['strict-transport-security']
        print(Fore.GREEN+"Present : Value = "+hstsInfo)
    else:
        print(Fore.RED+"[!] Not Found")
        
    ########### Content Security Policy (CSP) ###########
    print(Fore.YELLOW+"\n[@] Content Security Policy (CSP) : ",end = ' ')
    if 'content-security-policy' in headers: #checking for 'Content-Security-Policy' key in gheader
        cspInfo=r.headers['content-security-policy']
        print(Fore.GREEN+"Present : Value = "+cspInfo)
    else:
        print(Fore.RED+"[!] Not Found")
        
    ########### Cross Site Scripting Protection (X-XSS) ###########
    print(Fore.YELLOW+"\n[@] X-XSS-Protection : ",end = ' ')
    if 'x-xss-protection' in headers: #checking for 'x-xss-protection' key in gheader
        xssInfo=r.headers['x-xss-protection']
        print(Fore.GREEN+"Present : Value = "+xssInfo)
    else:
        print(Fore.RED+"[!] Not Found")
        
    ########## X-Frame-Options ###########
    print(Fore.YELLOW+"\n[@] x-frame-options : ",end = ' ')
    if 'x-frame-options' in headers: #checking for 'x-frame-options' key in gheader
        xFrameInfo=r.headers['x-frame-options']
        print(Fore.GREEN+"Present : Value = "+xFrameInfo)
    else:
        print(Fore.RED+"[!] Not Found")
        
    ########## X-Content-Type-Options ###########
    print(Fore.YELLOW+"\n[@] x-content-type-options : ",end = ' ')
    if 'x-content-type-options' in headers: #checking for 'x-content-type-options' key in gheader
        xContentInfo=r.headers['x-content-type-options']
        print(Fore.GREEN+"Present : Value = "+xContentInfo)
    else:
        print(Fore.RED+"[!] Not Found")    
    goBack()

#https://www.thesslstore.com/blog/http-security-headers/
