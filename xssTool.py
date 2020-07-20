import urllib
import os
import sys
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
import urllib.request
import http.client
import urllib.parse
from bs4 import BeautifulSoup
import requests
from colorama import Fore, Back, Style
import time

def wordlistimport(file,thelist):
	with open(file,'r') as f: #Importing Payloads from specified wordlist.
		print(Fore.BLUE+"[] Loading Payloads from wordlist"+Fore.RESET)
		for line in f:
			final = str(line.replace("\n",""))
			thelist.append(final)

def goBack():
    print(Fore.WHITE+"\n[+] Cross Site Scripting is Successfully Completed"+Style.RESET_ALL)
    while True:
        reTest=input(Fore.GREEN+"\n>> Do you want to test for XSS Again? ( y/n <or enter for 'n'> ) : "+Fore.RESET)
        if reTest=='y' or reTest=='Y':
            xssCheck() #Callinf XSS function again
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
            print(Fore.RED+Style.DIM+"[X] Invalid choice, enter Again : "+Style.RESET_ALL)

#Perform XSS Attack in Query
def XSSquery(site,query_pairs,components,xssParams):
	payloads = []
	progress=1
	wordlistimport('wordlist.txt',payloads) #Store the data of file in payloads list
	for script in payloads:
		print("\n")
		print(Fore.BLUE+"Checking for payload :: "+script)
		for key in query_pairs:
			if key in xssParams: #check if the key is present in xssParams list in which script will get embeded
				val=query_pairs[key] #set value of key in val
				for vals in val:
					vals=script
					query_pairs[key]=vals #to add script from payload into value of that key
			else:
				continue
		progress=progress+1
		new_query_str = urlencode(query_pairs)
		new_components = (
	        	components.scheme,
	        	components.netloc,
	        	components.path,
	        	components.params,
	        	new_query_str,
	        	components.fragment
	    	)
		newUrl=urlunparse(new_components) #Generate new URL with updated value, i.e script inside url
		print("Payload Url : ", newUrl)
		try:
			page = urllib.request.urlopen(newUrl) #Send Request for new URL
			sourcecode = page.read()
			if script.encode() in sourcecode: #if script written in requested page source code
				print(Fore.YELLOW+Style.BRIGHT+"[!!] XSS Vulnerable Found!")
			else:
				print(Fore.MAGENTA+"[--] XSS Vulnerability not Found!")
		except Exception: #urllib.error.HTTPError
			print(Fore.MAGENTA+"[--] XSS Vulnerability NOT Found!")
		except KeyboardInterrupt:
			print(Fore.RED+Style.DIM+"\n[X] You hit the interrupt key"+Style.RESET_ALL)
	return

#Perform XSS Attack inside Form
def XSSForm(site,XSSfields,methodType):
	payloads = []
	progress=1
	print(Fore.BLUE+"[] Performing XSS on given Field(s) : ",XSSfields)
	wordlistimport('wordlist.txt',payloads)
	for script in payloads:
		values={}
		print("\n")
		print(Fore.BLUE+"Checking for payload :: "+ script)
		for field in XSSfields:
		    #print(field)
		    field=field.replace("\"","")
		    values.update({field:script}) #set field name with value of script inside dictionary #try:
		    #print(values)
		    data = urllib.parse.urlencode(values).encode("utf-8")
		    req = urllib.request.Request(site,data)
		    response = urllib.request.urlopen(req)
		    html_content=response.read()
		    soup = BeautifulSoup(html_content,'html.parser')
		    get_script = soup.find_all('script')
		    myresult=' '.join([str(elem) for elem in get_script])
		    #print(myresult)
		    if script in myresult:
		        print(Fore.YELLOW+Style.BRIGHT+"[!!] XSS Vulnerablity Found!")
		    else:
		        print(Fore.MAGENTA+"[--] Vulnerability Not Found")
		    '''print(get_script)
		    if script in response.read(): #check if script is written inside Source Code
		        print(Fore.YELLOW+Style.BRIGHT+"[!!] XSS Vulnerablity Found!")
		    else:'''
		    #progress=progress+1
	#print("HI")

def XSSForm1(site,XSSfields,methodType):
	payloads = []
	progress=1
	print(Fore.BLUE+"[] Performing XSS on given Field(s) : ",XSSfields)
	wordlistimport('wordlist.txt',payloads)
	for script in payloads:
		values={}
		print("\n")
		print(Fore.BLUE+"Checking for payload :: "+ script)
		for field in XSSfields:
			field=field.replace("\"","")
			values.update({"\""+field+"\"":script}) #set field name with value of script inside dictionary #try:
		try:
		    req=requests.post(site,data=values)
		    #print(req.text)
		    if script in req.text: #check if script is written inside Source Code
			    print(Fore.YELLOW+Style.BRIGHT+"[!!] XSS Vulnerablity Found!")
		    else:
			    print(Fore.MAGENTA+"[--] Vulnerability Not Found")
		except Exception:
		    print(Fore.RED+Style.DIM+"[X] Unable to process request"+Style.RESET_ALL)
		    continue
		progress=progress+1

def checkAgain(site):
    XSSfields=[]
    InputNameList=[]
    page=requests.get(site)
    #print(Fore.BLUE+"\n[] No parameters in url, finding fields from page")
    soup=BeautifulSoup(page.content,'html.parser')
    inputs=soup.find_all('input') #Store name of all input fields in a list using BeautifulSoup
    for eachInput in inputs:
        eachInput=str(eachInput).replace("/>","")
        if "type=\"text\"" in eachInput or "type=\"email\"" in eachInput or "type=\"email\"" in eachInput or "type=\"search\"" in eachInput  or "type=\"hidden\"" in eachInput  :
            inputL=str(eachInput).split(" ")
            for formField in inputL:
                if "name=" in formField:
                    fieldName=str(formField).replace("name=","").replace("/","").replace(">","").replace(" ",",")
                    InputNameList.append(fieldName) #Name of input type of text/email/search
    if not InputNameList:
        print(Fore.RED+Style.DIM+"\n[X] No Input Fields Detected"+Style.RESET_ALL)
        repeat=1
        while repeat==1:
            restartChoice=input(Fore.GREEN+">> Do you want to test for some other url? (y/n <or enter for 'n'> ) : "+Fore.RESET)
            if restartChoice=='y' or restartChoice=='Y':
                repeat=0
                xssCheck()
            elif restartChoice=='n' or restartChoice=='N' or restartChoice=='':
                repeat=0
                return
            else :
                print(Fore.RED+Style.DIM+"\n[X] Invalid Choice,Enter Again"+Style.RESET_ALL)
				#repeat until valid choice is enterd
    print(Fore.BLUE+"[] Following Are The Inputs Names Where You Can Perform XSS : ")
    for fieldName in InputNameList:
        print(fieldName)
    print(Fore.GREEN+"\n>> In which parameter(s) you want to perform XSS.Enter y or n.")
    for fieldName in InputNameList :
        correct=1
        while correct==1:
            ch=input(Fore.GREEN+"[] "+fieldName+ " : "+Fore.RESET)
            if ch=="y" or ch=="Y":
                XSSfields.append(fieldName)
                correct=0
            elif ch=="n" or ch=="N":
                correct=0
                continue
            else:
                print(Fore.RED+Style.DIM+"\n[X] Invalid input. Enter again"+Style.RESET_ALL)
    while True:
        methodType=input(Fore.GREEN+"\n>> Enter the Method Type of form -> g for GET / p for POST : "+Fore.RESET)
        if methodType=="g" or methodType=="p" or methodType=="G" or methodType=="P":
            break
        else:
            print(Fore.RED+Style.DIM+"\n[X] Please Write Valid Input"+Style.RESET_ALL)
    XSSForm(site,XSSfields,methodType)
    goBack()
    		
def xssCheck():
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
		xssCheck()
	query_pairs=parse_qs(urlparse(site).query) #store url parameters  (ex q?="abc") in form of dictionary in query_pairs, where "q" will be key with value "abc"
	xssParams=[]
	if query_pairs : #check if the url is parameterised
		if len(query_pairs)==1: #If only one parameter present
			for key in query_pairs:
				XSSquery(site,query_pairs,components,query_pairs[key]) #Perform XSS in Query
		else: #If more than one parameters present
			print(Fore.CYAN+Style.DIM+"\n[] Following are the Parameters Detected From URL : "+Style.RESET_ALL)
			for parameter in query_pairs :
				print(parameter,end=',')
			print(Fore.WHITE+"\n\n In which parameter(s) you want to perform XSS.( y/n <or enter for 'n'> ) ") #
			for parameter in query_pairs :
				correct=1
				while correct==1:
					ch=input(Fore.GREEN+">> "+parameter + " : "+Fore.RESET)
					if(ch=="y" or ch=="Y"):
						xssParams.append(parameter) #Add those parameters to list on whoch XSS is to be done
						correct=0
					elif(ch=="n" or ch=="N" or ch==""):
						correct=0
						continue
					else:
						print(Fore.RED+Style.DIM+"\n[X] Invalid input. Enter again"+Style.RESET_ALL)
			XSSquery(site,query_pairs,components,xssParams) #Perform XSS in Query
		choiceL=input(Fore.WHITE+"\n\n Do you want to check for XSS inside the script? (Y/n) : ")
		if choiceL=="y" or choiceL=="Y":
		    checkAgain(site)
		else:
		    #goBack()
			print("HERE!")
	else : #No Parameters Present in Given URL
		XSSfields=[]
		InputNameList=[]
		page=requests.get(site)
		print(Fore.BLUE+"\n[] No parameters in url, finding fields from page")
		soup=BeautifulSoup(page.content,'html.parser')
		inputs=soup.find_all('input') #Store name of all input fields in a list using BeautifulSoup
		for eachInput in inputs:
			eachInput=str(eachInput).replace("/>","")
			if "type=\"text\"" in eachInput or "type=\"email\"" in eachInput or "type=\"email\"" in eachInput or "type=\"search\"" in eachInput  or "type=\"hidden\"" in eachInput  :
				inputL=str(eachInput).split(" ")
				for formField in inputL:
					if "name=" in formField:
						fieldName=str(formField).replace("name=","").replace("/","").replace(">","").replace(" ",",")
						InputNameList.append(fieldName) #Name of input type of text/email/search
		if not InputNameList:
			print(Fore.RED+Style.DIM+"\n[X] No Input Fields Detected"+Style.RESET_ALL)
			repeat=1
			while repeat==1:
				restartChoice=input(Fore.GREEN+">> Do you want to test for some other url? (y/n <or enter for 'n'> ) : "+Fore.RESET)
				if restartChoice=='y' or restartChoice=='Y':
					repeat=0
					xssCheck()
				elif restartChoice=='n' or restartChoice=='N' or restartChoice=='':
					repeat=0
					return
				else :
					print(Fore.RED+Style.DIM+"\n[X] Invalid Choice,Enter Again"+Style.RESET_ALL)
					#repeat until valid choice is enterd

		print(Fore.BLUE+"[] Following Are The Inputs Names Where You Can Perform XSS : ")
		for fieldName in InputNameList:
			print(fieldName)
		print(Fore.GREEN+"\n>> In which parameter(s) you want to perform XSS.Enter y or n.")
		for fieldName in InputNameList :
			correct=1
			while correct==1:
				ch=input(Fore.GREEN+"[] "+fieldName+ " : "+Fore.RESET)
				if ch=="y" or ch=="Y":
					XSSfields.append(fieldName)
					correct=0
				elif ch=="n" or ch=="N":
					correct=0
					continue
				else:
					print(Fore.RED+Style.DIM+"\n[X] Invalid input. Enter again"+Style.RESET_ALL)
		while True:
			methodType=input(Fore.GREEN+"\n>> Enter the Method Type of form -> g for GET / p for POST : "+Fore.RESET)
			if methodType=="g" or methodType=="p" or methodType=="G" or methodType=="P":
				break
			else:
				print(Fore.RED+Style.DIM+"\n[X] Please Write Valid Input"+Style.RESET_ALL)
		XSSForm(site,XSSfields,methodType) #Perform XSS in form
	goBack()

