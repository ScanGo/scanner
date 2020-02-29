import requests
import sys
import subprocess
import os
import http.client
from colorama import Fore, Back, Style
import time
#from http import cookies
from http.cookiejar import CookieJar, DefaultCookiePolicy

def update_progress(progress):
    length = 100
    block = int(round(length*progress))
    display = "{0}\r{1}[{2}]{3}".format(Fore.GREEN," "*15,"-"*block + " "*(length-block),Fore.RESET) #round(progress*100, 2)
    sys.stdout.write(display)
    sys.stdout.flush()
    
def actionCall(action):
    print(Fore.BLUE+action+Style.RESET_ALL)
    for i in range(100):
        time.sleep(0.05)
        update_progress(i/100.0)
    update_progress(1)
    print("\n")
    
def goBack():
    print(Fore.WHITE+"\n[+] Protection Against Cross Site Request Forgery Checked "+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do You Want To Test For XSRF Again ? (y/N) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            xsrfInfo() #Going Back to test For XSRF check
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
        xsrfInfo()

def xsrfInfo():
    link=input(Fore.GREEN+"\n>> Enter The URL of Login Page <http://domain.com> : "+Fore.RESET) #"http://www.quora.com"
    if 'http' not in link:
        link="http://"+link
    print(Fore.MAGENTA+"[] Checking The Correctness of Given URL")
    checklink(link)
    #since the url is correct:
    print(Fore.BLUE+"[] The Given URL is correct")
    print("[] Sending url request")
    r = requests.get(link) #sendind the given link request
    print(Fore.WHITE+"[.] Valid URL Given\n")
    actionCall("[!] Intiating check to find the presence of CSRF Token")
    #print(r.cookies)
    if 'csrftoken' in r.cookies :
        print(Fore.GREEN+"[@]CSRF TOKEN PRESENT!",end=' ')
        csrftoken = r.cookies['csrftoken']
        print(Fore.CYAN+"Value : "+csrftoken)
    elif 'XSRF-TOKEN' in r.cookies :
        print(Fore.GREEN+"[@]CSRF TOKEN PRESENT!",end=' ')
        csrftoken = r.cookies['XSRF-TOKEN']
        print(Fore.CYAN+"Value : "+csrftoken)
    elif 'X-CSRF-Token' in r.cookies :
        print(Fore.GREEN+"[@]CSRF TOKEN PRESENT!",end=' ')
        csrftoken = r.cookies['XSRF-TOKEN']
        print(Fore.CYAN+"Value : "+csrftoken)
    else :
        print(Fore.RED+"\n[!]Unable to find CSRF Token!\n")

    actionCall("\n[!] Intiating cookies configuration check Defending against CSRF!")
    print(Fore.WHITE+"[@]Cookie Name \t | \t Attribute"+Fore.YELLOW)
    for cookie in r.cookies:
        cookieData=cookie.__dict__
        print("[.]"+cookie.name,end="\t\t\t")
        chData=cookie._rest
        print(chData)
    print(Fore.RED+"\n[!] Best Configuration to defend against CSRF : SameSite=Strict")    
    goBack()

