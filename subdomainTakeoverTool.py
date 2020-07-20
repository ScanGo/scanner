import requests
from bs4 import BeautifulSoup
import re
import sys
import time
from colorama import Fore, Back, Style
import os
import subprocess
import http.client
import urllib
#from terminaltables import AsciiTable
import socket
import sublist3r

#Page data that can be vulnerable to Subdomain Takeover
fingerprints=["The specified bucket does not exist","Repository not found","Bad Request: ERROR: The request could not be satisfied","Fastly error","The feed has not been found","The thing you were looking for is no longer here, or never was","There isn't a Github Pages site here","We could not find what you're looking for","No settings were found for this company","No such app","is not a registered InCloud YouTrack","Project doesnt exist","project not found","Whatever you were looking for doesn't currently exist at this address","The requested URL was not found on this server.","This UserVoice subdomain is currently available!","Do you Want to register"]

subdomains=[]
dashes="-"*130

def goBack():
    print(Fore.WHITE+"\n\n"+"Subdomain Takeover Check Is Successfully Completed "+Style.RESET_ALL)
    while True:
        reTest=input("\nDo You Want To Test For Sundomain Takeover Again? ( y/N ) : ")
        if reTest=='y' or reTest=='Y':
            subdomainFunction() #calling subdomain takeover function again
        elif reTest=='n' or reTest=='N' or reTest=='':
            while True:
                choice=input(Fore.BLUE+"Press Q to Quit or ENTER to go back(b) to index : "+Style.RESET_ALL)
                if(choice=='Q' or choice=='q'):
                    sys.exit() #exit program
                elif choice=='' or choice=='b':
                    print("Going back to the Index of Medium Level Vulnerability Scanner")
                    return
                else:
                    print(Fore.RED+"[X] Invalid choice, enter Again : "+Style.RESET_ALL)
        else :
            print(Fore.RED+"[X] Invalid choice, Enter Again : "+Style.RESET_ALL)

def subdomGather(domain):
    domains=[]
    ports=None
    silent=True
    verbose= False
    enable_bruteforce= False
    no_threads=40
    engines=None
    print(Fore.YELLOW+"\n[-] Fetching Subdomains for "+domain+" using sublister, this will take time\n\n")
    print(Fore.WHITE+"[...] Ignore the following error! [...]"+Style.RESET_ALL)
    subdomain = sublist3r.main(domain, no_threads,"save.txt", ports, silent, verbose, enable_bruteforce,engines)
    return subdomain

def checkDomain(domain):
    print(Fore.BLUE+"\n[] Checking the authenticity of domain given"+Style.RESET_ALL)
    try:
        request = http.client.HTTPConnection(domain) #Connect with domain
        request.connect()
        return
    except Exception:
        print(Fore.RED+"[X] Invalid domain name given. Try again \n\n"+Style.RESET_ALL)
        subdomainFunction()

def dnsDumpster(domain):
    print(Fore.BLUE+"[] Finding subdomains using dnsDumpster"+Style.RESET_ALL)
    s = requests.Session()
    pageUrl="https://dnsdumpster.com/" #used to gather subdomains of a domain
    res=requests.get(pageUrl)
    soup = BeautifulSoup(res.content, 'html.parser')
    csrf_middleware = soup.findAll('input', attrs={'name': 'csrfmiddlewaretoken'})[0]['value']#to retrive the token
    cookies = {'csrftoken': csrf_middleware}
    headers = {'Referer': pageUrl}
    data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain} #Set targetIP to domain
    r = s.post(pageUrl,cookies=cookies, data = data, headers=headers) #send the data with token, domain using dnsDumpster as referer
    soup = BeautifulSoup(r.content, 'html.parser') #parse the content of request
    tables = soup.find_all('table', {"class":"table"}) #The subdomain data is stored in table
    for table in tables:
        rows=table.find_all('tr')
        for row in rows:
            tds = row.find_all('td',{"class": "col-md-4"})
            domain_found = str(tds).split('<br/>')
            dom=domain_found[0]
            if domain in dom: #check if our domain exist in fetched domain result from page
                subdomain=dom.split('>')
                sub=subdomain[1]
                if sub not in subdomains :
                    subdomains.append(sub) #add subdomains to the list
                else :
                    continue
    return subdomains

def dnsBrute(domain):
    print(Fore.BLUE+"[] Finding subdomains using dnsBrute"+Style.RESET_ALL)
    x=subprocess.check_output(['nmap','--script','dns-brute',domain]) #store the nmap dns-brute command result in variable
    cmd_data=str(x).split(" ")
    for data in cmd_data :
        if "."+domain in data :
            if data not in subdomains:
                subdomains.append(data) #add subdomains to the list
            else:
                continue
    return subdomains

def crt_sh(domain):
    print(Fore.BLUE+"[] Finding subdomains using CRT_SH"+Style.RESET_ALL)
    crtUrl="https://crt.sh/?q=%."+domain+"&output=json" #to get json file, easier to process
    response=requests.get(crtUrl)
    if response.status_code == 200:
        for (key,value) in enumerate(response.json()): #enumerate creats list with key and values for each json record
            if "*" not in value['name_value']:
                subdomains.append(value['name_value'])  #key name_value has the subdomain as value
    return subdomains

def filterSubdomains(domain):
    print(Fore.BLUE+"\n[] Gathering appropriate subdomains by fetching unique results"+Style.RESET_ALL)
    usubdomains=[]
    #to get unique subdomains
    for i in range (0,len(subdomains)):
        if subdomains[i].endswith('.'):
            subdomains[i]=subdomains[i][:-1]
        if (subdomains[i]==domain):
            continue
        if(subdomains[i] not in usubdomains):
            usubdomains.append(subdomains[i])
    return usubdomains

def cnameFetch(subdom):
    cname="na"
    cmd=subprocess.check_output(['dig',str(subdom)]) #store dig command result in a variable
    cmd_data=str(cmd).split("\\n")
    for data in cmd_data :
        if "CNAME" in data : #checking presence of cname in resultant data
            if '\\t' in data :
                lineData=data.split("\\t")
            lineData=' '.join(lineData).split() #Eliminate all empty strings inside the list
            CNAMEindex=lineData.index('CNAME')
            cname=lineData[CNAMEindex+1] #output : cname [] ,the next data is the required value of cname
    return(cname)

def subdomCheck(subdomainList):
    print(dashes)
    #tableHeadings=["Subdomain Name ","IP ADDRESS","C-NAME","RESPONSE","VULNERABLE?"] #headings of the table
    print('{:<35s}{:>20s}{:>30s}{:>15s}{:>25s}'.format("Subdomain Name ","IP ADDRESS","C-NAME","RESPONSE","VULNERABLE?"))
    print(dashes)
    for subdom in subdomainList:
        print("\n")
        subdomRow=[] #for printing in table
        resultTable=[]
        #subdomRow.append(subdom)
        print('{:<35s}'.format(subdom),end=" ")
        try:
            request = http.client.HTTPConnection(subdom)
            ipAddress=socket.gethostbyname(subdom) #to get IP ADDRESS Of the domain or Subdomain
            #subdomRow.append(ipAddress)
            #subdomRow.append(format(cnameFetch(subdom))) #to get cname value
            print('{:>20}'.format(ipAddress),end=" ")
            print('{:>30s}'.format(cnameFetch(subdom)),end=" ")
            url="https://"+subdom
            try:
                page = urllib.request.urlopen("https://"+subdom,timeout=2)
                url="https://"+subdom
            except urllib.error.URLError:
                try :
                    page = urllib.request.urlopen("http://"+subdom,timeout=2)
                    url="http://"+subdom
                except urllib.error.URLError:
                    url="https://"+subdom
            try:
                page = urllib.request.urlopen("https://"+subdom,timeout=5) #request for subdomain Connection
                ResponseStatus=page.getcode()
                #subdomRow.append(ResponseStatus)
                print('{:>17d}'.format(ResponseStatus),end=" ")
                sourcecode = page.read()
                sourcecod=sourcecode.splitlines()
                vuln=False
                for line in sourcecod: #traverse each line in sourcecode
                    if isinstance(line,str):
                        line.encode()
                    for fingerprint in fingerprints:
                        if re.search(fingerprint.encode(),line,re.IGNORECASE): #check if fingerprint present in the source code
                            #subdomRow.append("Yes") # vulnerable if present
                            print('{:>25s}'.format("Yes"))
                            vul=True
                            break
                        else:
                            continue
                if(vuln is False):
                    #subdomRow.append("No") #not vulnerable if fingerprint not present
                    print('{:>25s}'.format("No"))
            except urllib.error.HTTPError as e:
                ResponseStatus=e.code
                print('{:>17d}'.format(ResponseStatus),end=" ")
                print('{:>25s}'.format("Probably"))
                #subdomRow.append(ResponseStatus)
                #subdomRow.append("No")
            except urllib.error.URLError:
                print('{:>17d}'.format("50x"),end=" ")
                print('{:>25s}'.format("inconclusive"))
                #subdomRow.append("502")
                #subdomRow.append("No")
                print('{:>17d}'.format("-"),end=" ")
                print('{:>25s}'.format("inconclusive"))
                #subdomRow.append("-")
                #subdomRow.append("incompetent")
        except Exception :
            #print(Fore.RED+"\nConnection Error"+Style.RESET_ALL)
            #subdomRow.append("Connection Error")
            continue
        #resultTable.append(tableHeadings)
        #resultTable.append(subdomRow)
        #table = AsciiTable(resultTable) #To print in table form
        #print (table.table,"\n")

def subdomCheck1(subdomainList):
    #print(dashes)
    for subdom in subdomainList:
        Sdictionary={}
        ResponseStatus=0
        cname="NA"
        Sdictionary.update({"SUBDOMAIN NAME":subdom})
        ip=1
        try:
            request = http.client.HTTPConnection(subdom)
            #print(request)
            ipAddress=socket.gethostbyname(subdom)
            Sdictionary.update({"IP ADDRESS":ipAddress})
            ip=1
        except Exception:
            Sdictionary.update({"IP ADDRESS":"Unable to connect"})
            ip=0
        if ip==1:
            cname=cnameFetch(subdom)
            Sdictionary.update({"CNAME":cname})
        #print(Sdictionary)
        url=""
        if ip==1:
            try:
                page = urllib.request.urlopen("https://"+subdom,timeout=5)
                url="https://"+subdom
            except urllib.error.URLError:
                page = urllib.request.urlopen("http://"+subdom,timeout=5)
                url="http://"+subdom
            ResponseStatus=page.getcode()
            Sdictionary.update({"Responce Code":ResponseStatus})
            sourcecode = page.read()    
            sourcecod=sourcecode.splitlines()
            vuln=False
            for line in sourcecod:
                if isinstance(line,str):
                    line.encode()
            for fingerprint in fingerprints:
                if re.search(fingerprint.encode(),line,re.IGNORECASE):
                    #print("VULNERABLE")
                    Sdictionary.update({"Vulnerable?":"VULNERABLE"})
                    vuln=True
                    break
            if vuln==False:
                #print("NOT VULNERABLE")
                Sdictionary.update({"Vulnerable?":"NOT VULNERABLE"})
        if "Vulnerable?" not in Sdictionary:
            Sdictionary.update({"Vulnable?":"CAN NOT SAY!"})
        #print (Sdictionary)
        for key,value in Sdictionary.items():
            if key == "SUBDOMAIN NAME":
                print(Fore.WHITE+dashes)
            print(key,":",value)
        print("\n")    
                       
def subdomainFunction():
    subdomains=[]
    print(Fore.WHITE+"[][] Please enter the domain in a format "+Fore.YELLOW+"<domainName>.com (example : abc.com)"+Fore.WHITE+" [][]"+Style.RESET_ALL)
    domain=input(Fore.MAGENTA+"\n[#] Enter here : "+Style.RESET_ALL)
    checkDomain(domain) #check for correctness of domain
    subTest=input("Do You Want To Gather Subdomains using Sublister? ( y/N ) : ")
    if subTest=='y' or subTest=='Y':
        finalSubdomains=subdomGather(domain)
    else :     
        print(Fore.CYAN+"\n[] Calling methods to find subdomains one by one"+Style.RESET_ALL)
        dnsDumpster(domain)
        dnsBrute(domain)
        crt_sh(domain)
        finalSubdomains=filterSubdomains(domain)
    print(Fore.CYAN+"\n\n ALL POSSIBLE SUBDOAMINS GATHERED SUCCESSFULY \n\n"+Style.RESET_ALL)
    subdomCheck1(finalSubdomains)
    goBack()
#subdomainFunction()
