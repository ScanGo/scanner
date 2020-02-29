import sys
import subprocess
import os
import http.client
from colorama import Fore, Back, Style

def goBack():
    print(Fore.WHITE+"\n[+] SPF LOOKUP COMPLETED "+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do you want to check for SPF Again? (y/N) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            spfCheck() #Going back spf details verification function
        elif reTest=='n' or reTest=='N' or reTest=='':
            while True:
                choice=input(Fore.GREEN+"\n>> Press Q to Quit or ENTER to go back(b) to index : "+Style.RESET_ALL)
                if(choice=='Q' or choice=='q'):
                    sys.exit()
                elif choice=='' or choice=='b':
                    print(Fore.BLUE+"[-] Going back to the Index of Medium Level Vulnerability Scanner"+Fore.RESET)
                    return #Back to Index
                else:
                    print(Fore.RED+Style.DIM+"[X] Invalid choice, enter Again : "+Style.RESET_ALL)
        else :
            print(Fore.RED+Style.DIM+"[X] Invalid choice, expected value not Entered : "+Style.RESET_ALL)


def checkDomain(domain):
    print(Fore.MAGENTA+"\n[] Checking the correctness of domain given"+Style.RESET_ALL)
    try:
        request = http.client.HTTPConnection(domain) #connect with given domain
        request.connect()
        return
    except Exception:
        print(Fore.RED+Fore.DIM+"[X] Invalid domain name given. Try again \n\n"+Style.RESET_ALL)
        spfCheck() #Back to the start to ftpCheck()

def spfCheckFunction(domain):
    cmd=subprocess.check_output(['nslookup','-type=txt',domain]) #to store output of command in variable
    cmd_data=str(cmd).split("\\n") #storing data in a list
    for data in cmd_data :
        if "text" in data :
            data=data.replace("\"","")
            lineData=data.split(" ")
            lineData=' '.join(lineData).split() #Eliminate all empty strings inside the list
            record=lineData[2:]
            recordString=' '.join([str(element) for element in record])
            if "redirect" in recordString :
                redirectR=recordString.split("redirect=")
                spfCheckFunction(redirectR[1])
                return 1
            for word in record:
                if word.startswith("v="):
                    print(Fore.WHITE+"\n"+"-"*56)
                    print(Fore.CYAN+"SPF RECORD FOUND : "+' '.join([str(element) for element in record]))
                    #print("SPF Record Version : "+record[0])
                    print(Fore.WHITE+"-"*56+Style.RESET_ALL)
                    match=record[len(record)-1]
                    if(match=="-all"):
                        print(Fore.GREEN+"\n[^] REJECTION LEVEL : Fail "+Fore.RED+"Configuration Type : "+Fore.WHITE+"BEST")
                        #(reject or fail them - don't deliver the email if anything does not match)
                    elif(match=="~all"):
                        print(Fore.YELLOW+"\n[#] REJECTION LEVEL : Soft Fail "+Fore.RED+"Configuration Type : "+Fore.WHITE+"Good, Mostly used.")
                        #(soft-fail them - accept them, but mark it as 'suspicious')
                    elif(match=="+all"):
                        print(Fore.RED+"\n[!] REJECTION LEVEL : Pass "+Fore.RED+"Configuration Type : "+Fore.WHITE+"Worst. Please Change if Possible")
                        #(pass regardless of match - accept anything from the domain)
                    elif(match=="?all"):
                        #(neutral - accept it, nothing can be said about the validity if there isn't an IP match)
                        print(Fore.YEllOW+"\n[@] REJECTION LEVEL : Neutral "+Fore.RED+"Configuration Type : "+Fore.WHITE+"Okay! If you have large domains")
                    return 1
    print(Fore.RED+"[!] Unable to connect with server to fetch for SPF Record!"+Style.RESET_ALL)
    goBack()
    return 0         
      
def spfCheck():
    spf=0
    domain=input(Fore.GREEN+"\n>> Enter the domain name <domain.com> : "+Fore.RESET)
    checkDomain(domain) #Check the Connection with domain
    print(Fore.BLUE+"[] Valid Domain")
    print("[] Fetching SPF Details")
    check=spfCheckFunction(domain)
    if check==0:
        print(Fore.RED+"\n\n[!] SPF RECORD NOT PRESENT !"+Style.RESET_ALL)
        
    goBack() #Completed spfCheck
    
#https://support.gfi.com/hc/en-us/articles/360013000093-How-to-check-and-read-a-Sender-Policy-Framework-record-for-a-domain

