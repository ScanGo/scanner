import urllib
import os
import sys
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
import urllib.request
import http.client
from bs4 import BeautifulSoup
import requests
from colorama import Fore, Back, Style
import time

def goBack():
    print(Fore.WHITE+"\n[+] Possible File Inclusion variables successfully detected "+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do You Want To Fetch File Inclusion Variables Again? ( y/N ) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            fileInclusionCheck()
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

def fileInclusionCheck():
    count=1
    #fileDict={}
    fileInc=0
    site = input(Fore.GREEN+"\n>> Enter URL <http(s)://domain.com> : "+Fore.RESET)
    if "http://" in site:
        pass
    elif "https://" in site:
        pass
    else:
        site = "http://"+site
    print(Fore.MAGENTA+"[] Checking for the correctness of given url"+Fore.RESET)
    try:
        components = urlparse(site) #parsing the url
        exactDomain = '{uri.scheme}://{uri.netloc}/'.format(uri=components) #for 'http://domain.com/questions/1234567/blah-blah-blah-blah' gives'http://domain.com/' i.e. the domain
        domain = exactDomain.replace("https://","").replace("http://","").replace("www.","").replace("/","")
        request = http.client.HTTPConnection(domain)
        request.connect()
        print(Fore.BLUE+"[] The domain is correct"+Fore.RESET)
    except Exception:
        print(Fore.RED+Style.DIM+"\n[X] Invalid Url, Try Again"+Style.RESET_ALL) #Unable to connect with domain
        fileInclusionCheck()
    InputNameList=[]
    page=requests.get(site)
    #page=str(page.content).split('<')
    #page=' '.join(page)
    #print("\n\n\n\n\n\n\n\n")
    #print(page)
    soup=BeautifulSoup(page.text,'lxml')
    #print(soup.prettify)
    #print("\n\n\n\n\n\n\n\n")
    inputs=soup.find_all('input') #Store name of all input fields in a list using BeautifulSoup
    for eachInput in inputs:
        fileDict={}
        eachInput=str(eachInput).replace("/>","")
        if "type=\"file\"" in eachInput :
            fileInc=fileInc+1
            inputL=str(eachInput).split(" ")
            fileDict.update({"ID":count})
            count=count+1
            for formField in inputL:
                if "name=" in formField:
                    fieldName=str(formField).replace("name=","").replace("/","").replace(">","").replace(" ",",")
                    InputNameList.append(fieldName) #Name of input type of text/email/search
                    fileDict.update({"Input Name":fieldName})
                if "id=" in formField:
                    fieldName=str(formField).replace("id=","").replace("/","").replace(">","").replace(" ",",")
                    InputNameList.append(fieldName)
                    fileDict.update({"ID Name":fieldName})
                if "accept=" in formField:
                    fieldName=str(formField).replace("accept=","").replace("/","").replace(">","").replace(" ",",")
                    InputNameList.append(fieldName) #Name of input type of text/email/search
                    fileDict.update({"Accepting Type":fieldName})
            if not InputNameList:
                print(Fore.RED+Style.DIM+"\n[X] No Input Fields Detected"+Style.RESET_ALL)
    print(Fore.WHITE+"\n[] Following Is/Are The Inputs Names Where You Can Upload File : "+Fore.YELLOW)
    #for fieldName in InputNameList:
    #print(fieldName)
    #print("\n\n\n\n",fileInc)
    for key,value in fileDict.items():
        if key == "ID":
            print ("\n","-"*40)
        print (key, ":", value,"\n")
        if key == "ID Name":
            print ("-"*40,"\n\n")
    goBack()
#fileInclusionCheck()

#https://smallpdf.com/jpg-to-pdf
#
