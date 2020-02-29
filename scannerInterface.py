from colorama import Fore, Back, Style
import os
import time
import sys
import subprocess
#modules to check for high level vulnerabilities
import sqlInjectionTool
#import xssTool
import subdomainTakeoverTool

#import htmlInjectionTool

#modules to check for Medium level vulnerabilities
#import brutePassTool
#import corsTool
import missSPF
import dnsMisconf
import httpHeaderInjection


#modules to check for informative vulnerabilities
import openPortsDetectionTool
import infoHTTP
#import ftpCheckTool
import serverInfoTool
import impHeaders
import xsrfCheck
#import XXSS_Tool

subprocess.check_output(['resize','-s','50','140']) #to resize the terminal screen in order to enhance the view
os.system('clear') #clear all the previous junk on terminal

#main banner
print(Fore.RED+Style.DIM+"""
            ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██████╗  █████╗ ██████╗ ██╗██╗     ██╗████████╗██╗   ██╗
            ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██║██║     ██║╚══██╔══╝╚██╗ ██╔╝
            ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██████╔╝███████║██████╔╝██║██║     ██║   ██║    ╚████╔╝
            ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║██╔══██╗██║██║     ██║   ██║     ╚██╔╝
             ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗██║  ██║██║  ██║██████╔╝██║███████╗██║   ██║      ██║
              ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚══════╝╚═╝   ╚═╝      ╚═╝
                                                                                                                            
                        ██████╗ ███████╗████████╗███████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗
                        ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
                        ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║
                        ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║
                        ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║
                        ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                                                                            
    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗    ██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗
    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝    ██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝
    ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝     ██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║   
    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝      ██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║   
    ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║       ██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║   
    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝       ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   
                                                                                                                             """+Style.RESET_ALL)

#function to display progress bar
def update_progress(progress):
    length = 100
    block = int(round(length*progress))
    display = "{0}\r{1}[{2}]{3}".format(Fore.GREEN," "*15,"!"*block + " "*(length-block),Fore.RESET) #round(progress*100, 2)
    sys.stdout.write(display)
    sys.stdout.flush()

#headstart to call the index ans enhance
def fetchIndex():
    print(Fore.YELLOW+Style.BRIGHT+"[+] Coded by : Gunisha Chhabra & Namrata yadav")
    print("[+] Scanner Version : 1.0"+Style.RESET_ALL)
    print(Fore.BLUE+"\n\nFetching Main Index"+Style.RESET_ALL)
    for i in range(100):
        time.sleep(0.01)
        update_progress(i/100.0)
    update_progress(1)
    print("\n")
    PrimaryOptions()

#To display calling of function along with progress bar
def actionCall(action):
    print(Fore.BLUE+action+Style.RESET_ALL)
    for i in range(100):
        time.sleep(0.01)
        update_progress(i/100.0)
    update_progress(1)
    print("\n")

#Primary option list
def PrimaryOptions():
    print("%s\nLevels of Vulnerability that can be detected %s \n"%(Fore.WHITE,Style.RESET_ALL))
    print(Fore.GREEN+"[1] High Severity Vulnerablity")
    print("[2] Medium Severity Vulnerability")
    print("[3] Informative Vulnerability"+Fore.GREEN)
    print(Fore.BLUE+"[4] Exit"+Fore.RESET)
    try:
        optionP=int(input(Fore.GREEN+"\n>> Enter Your Choice : "+Fore.RESET))
        if(optionP<=0 or optionP>=5): #If unexpected input is passed
            print(Fore.RED+Style.DIM+"Invalid Option. Enter Again"+Style.RESET_ALL)
            time.sleep(0.5)
            PrimaryOptions()
        elif(optionP==4):
            print(Fore.WHITE+"You Have Called To Terminate The Program"+Fore.RESET)
            actionCall("Terminating Execution")
            sys.exit()
        else :
            SecondaryOption(optionP)
    except (Exception): #Occurs when input is not an integer
        print(Fore.RED+Style.DIM+"Input of invalid type is entered"+Style.RESET_ALL)
        time.sleep(0.5)
        PrimaryOptions() #Going back to the primary option list

#Secondary option list
def SecondaryOption(option):
    if option==1:
        #printing all the types of high level vulnerabilities support by this application
        print("%s\nList Of High Severity Vulnerabilities That Can Be Detected %s \n"%(Fore.WHITE,Style.RESET_ALL))
        print(Fore.GREEN+"[1] SQL Injection (Error Based)")
        print("[2] Subdomain Takeover")
        print("[3] Go Back")
        print(Fore.BLUE+"[4] Exit"+Fore.RESET)
        try:
            optionS=int(input(Fore.GREEN+"\n>>Enter Your Choice : "+Fore.RESET))
            if optionS==1:
                actionCall("\n\nCalling Function To Scan For SQL Injection.")
                print(Fore.RED+Style.DIM+"""
            ███████╗ ██████╗ ██╗         ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗
            ██╔════╝██╔═══██╗██║         ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
            ███████╗██║   ██║██║         ██║██╔██╗ ██║     ██║█████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║
            ╚════██║██║▄▄ ██║██║         ██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║
            ███████║╚██████╔╝███████╗    ██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║
            ╚══════╝ ╚══▀▀═╝ ╚══════╝    ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝\n\n"""+Style.RESET_ALL)
                sqlInjectionTool.sqliAttack() #redirecting to sql Injection tool
                SecondaryOption(1)
            elif optionS==2:
                actionCall("\n\nCalling function to scan for Subdomain Takeover.")
                print(Fore.RED+Style.DIM+"""
                            ███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
                            ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
                            ███████╗██║   ██║██████╔╝██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
                            ╚════██║██║   ██║██╔══██╗██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
                            ███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
                            ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝

                                ████████╗ █████╗ ██╗  ██╗███████╗ ██████╗ ██╗   ██╗███████╗██████╗
                                ╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗
                                   ██║   ███████║█████╔╝ █████╗  ██║   ██║██║   ██║█████╗  ██████╔╝
                                   ██║   ██╔══██║██╔═██╗ ██╔══╝  ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
                                   ██║   ██║  ██║██║  ██╗███████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║
                                   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝\n\n"""+Style.RESET_ALL)
                subdomainTakeoverTool.subdomainFunction() #redirecting to subdomain Takeover tool
                SecondaryOption(1)
            elif optionS==3:
                print(Fore.BLUE+"[] Going back to PrimaryOptions."+Fore.RESET) #redirecting to primary options
                PrimaryOptions()
            elif optionS==4:
                print(Fore.WHITE+"\n[.] You Have Called To Terminate The Program"+Fore.RESET)
                actionCall("Terminating Execution")
                sys.exit() #exit application
            else:
                print(Fore.RED+Style.DIM+"[X] Invalid choice! Do it again"+Style.RESET_ALL)
                time.sleep(0.5)
                SecondaryOption(1)
        except(Exception):
            print(Fore.RED+Style.DIM+"[X] Input of invalid type is entered"+Style.RESET_ALL)
            time.sleep(0.5)
            SecondaryOption(1)
    if option==2:
        #printing all the types of medium level vulnerabilities support by this application
        print("%s\nList Of Medium Level Vulnerabilities That CAN Be Detected%s \n"%(Fore.WHITE,Style.RESET_ALL))
        print(Fore.GREEN+"[1] Missing SPF")
        print("[2] DNS Misconfiguration")
        print("[3] HTTP Header Injection")
        print("[4] Go Back")
        print(Fore.BLUE+"[5] Exit")
        try:
            optionS=int(input(Fore.GREEN+"\n>> Enter Your Choice : "+Fore.RESET))
            if optionS==1:
                actionCall("\n\nCalling Function To Scan For Missing SPF")
                print(Fore.RED+Style.DIM+"""
                            ███╗   ███╗██╗███████╗███████╗██╗███╗   ██╗ ██████╗     ███████╗██████╗ ███████╗
                            ████╗ ████║██║██╔════╝██╔════╝██║████╗  ██║██╔════╝     ██╔════╝██╔══██╗██╔════╝
                            ██╔████╔██║██║███████╗███████╗██║██╔██╗ ██║██║  ███╗    ███████╗██████╔╝█████╗  
                            ██║╚██╔╝██║██║╚════██║╚════██║██║██║╚██╗██║██║   ██║    ╚════██║██╔═══╝ ██╔══╝  
                            ██║ ╚═╝ ██║██║███████║███████║██║██║ ╚████║╚██████╔╝    ███████║██║     ██║     
                            ╚═╝     ╚═╝╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝     ╚══════╝╚═╝     ╚═╝     
                                                                                \n\n"""+Style.RESET_ALL)
                missSPF.spfCheck() #redirecting to missing SPF Detection Tool
                SecondaryOption(2)
            elif optionS==2:
                actionCall("\n\nCalling Function To Scan For DNS Misconfiguration.")
                print(Fore.RED+Style.DIM+"""
                            ██████╗ ███╗   ██╗███████╗    ███████╗ ██████╗ ███╗   ██╗███████╗    
                            ██╔══██╗████╗  ██║██╔════╝    ╚══███╔╝██╔═══██╗████╗  ██║██╔════╝       
                            ██║  ██║██╔██╗ ██║███████╗      ███╔╝ ██║   ██║██╔██╗ ██║█████╗      
                            ██║  ██║██║╚██╗██║╚════██║     ███╔╝  ██║   ██║██║╚██╗██║██╔══╝      
                            ██████╔╝██║ ╚████║███████║    ███████╗╚██████╔╝██║ ╚████║███████╗    
                            ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝    
                                                                     
                            ████████╗██████╗  █████╗ ███╗   ██╗███████╗███████╗███████╗██████╗   
                            ╚══██╔══╝██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔════╝██╔════╝██╔══██╗  
                               ██║   ██████╔╝███████║██╔██╗ ██║███████╗█████╗  █████╗  ██████╔╝  
                               ██║   ██╔══██╗██╔══██║██║╚██╗██║╚════██║██╔══╝  ██╔══╝  ██╔══██╗  
                               ██║   ██║  ██║██║  ██║██║ ╚████║███████║██║     ███████╗██║  ██║  
                               ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝\n\n"""+Style.RESET_ALL)
                dnsMisconf.dnsMisconf() #redirecting to DNS Zone Transfer Check Tool
                SecondaryOption(2)
            elif optionS==3:
                actionCall("\n\nCalling function to scan for Subdomain Takeover.")
                print(Fore.RED+Style.DIM+"""
                    ██╗  ██╗████████╗████████╗██████╗     ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗
                    ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗    ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗    
                    ███████║   ██║      ██║   ██████╔╝    ███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝    
                    ██╔══██║   ██║      ██║   ██╔═══╝     ██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗    
                    ██║  ██║   ██║      ██║   ██║         ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║    
                    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝         ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝    
                                                                                          
                            ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗
                            ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
                            ██║██╔██╗ ██║     ██║█████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║
                            ██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║
                            ██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║
                            ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                                          \n\n"""+Style.RESET_ALL)
                httpHeaderInjection.httpHeaderInj() #redirecting to Header Injection tool
                SecondaryOption(1)
            elif optionS==4:
                print("Going back to PrimaryOptions.")
                PrimaryOptions()
            elif optionS==5:
                print(Fore.WHITE+"\n[.] You Have Called To Terminate The Program")
                actionCall("Terminating Execution")
                sys.exit() #Exit Program
            else:
                print(Fore.RED+Style.DIM+"[X] Invalid choice! Enter Again"+Style.RESET_ALL)
                time.sleep(0.5)
                SecondaryOption(2)
        except(Exception):
            print(Fore.RED+"[X] Input is of invalid type. Enter Again"+Style.RESET_ALL)
            time.sleep(0.5)
            SecondaryOption(2)

    if option==3:
        #printing all the types of Informative vulnerabilities support by this application
        print("%s\nList Of Informative Vulnerabilities That Can Be Detected : %s \n"%(Fore.WHITE,Style.RESET_ALL))
        print(Fore.GREEN+"[1] Detect Open Ports")
        print("[2] Internal Information Disclosure in HTTP Headers")
        print("[3] Server Information Disclosure")
        print("[4] Check For Important Security Headers")
        print("[5] Protection Against Cross-Site Request Forgery")
        print(Fore.BLUE+"[6] Go back")
        print(Fore.BLUE+"[7] Exit")
        try:
            optionS=int(input(Fore.GREEN+"\n>> Enter Your Choice : "+Fore.RESET))
            if optionS==1:
                actionCall("\n\nCalling Function To Scan For Open Ports")
                print(Fore.RED+Style.DIM+"""
                                        ██████╗ ███████╗████████╗███████╗ ██████╗████████╗
                                        ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
                                        ██║  ██║█████╗     ██║   █████╗  ██║        ██║
                                        ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║
                                        ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║
                                        ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝

                         ██████╗ ██████╗ ███████╗███╗   ██╗    ██████╗  ██████╗ ██████╗ ████████╗███████╗
                        ██╔═══██╗██╔══██╗██╔════╝████╗  ██║    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝
                        ██║   ██║██████╔╝█████╗  ██╔██╗ ██║    ██████╔╝██║   ██║██████╔╝   ██║   ███████╗
                        ██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║    ██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║
                        ╚██████╔╝██║     ███████╗██║ ╚████║    ██║     ╚██████╔╝██║  ██║   ██║   ███████║
                         ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝\n\n"""+Style.RESET_ALL)
                openPortsDetectionTool.openPortDetection() #redirecting to open ports Detection Tool
                SecondaryOption(3)
            elif optionS==2:
                actionCall("\n\nCalling function to Scan For Internal Information Disclosure in HTTP Headers")
                print(Fore.RED+Style.DIM+"""
                ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗                       
                ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║                       
                ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║                       
                ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║                       
                ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║                       
                ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝                       
                                                                                                               
                   ██████╗ ██╗███████╗ ██████╗██╗      ██████╗ ███████╗██╗   ██╗██████╗ ███████╗
                   ██╔══██╗██║██╔════╝██╔════╝██║     ██╔═══██╗██╔════╝██║   ██║██╔══██╗██╔════╝
                   ██║  ██║██║███████╗██║     ██║     ██║   ██║███████╗██║   ██║██████╔╝█████╗
                   ██║  ██║██║╚════██║██║     ██║     ██║   ██║╚════██║██║   ██║██╔══██╗██╔══╝
                   ██████╔╝██║███████║╚██████╗███████╗╚██████╔╝███████║╚██████╔╝██║  ██║███████╗
                   ╚═════╝ ╚═╝╚══════╝ ╚═════╝╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
                                                                                                               
    ██╗███╗   ██╗    ██╗  ██╗████████╗████████╗██████╗     ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗
    ██║████╗  ██║    ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗    ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
    ██║██╔██╗ ██║    ███████║   ██║      ██║   ██████╔╝    ███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗
    ██║██║╚██╗██║    ██╔══██║   ██║      ██║   ██╔═══╝     ██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║
    ██║██║ ╚████║    ██║  ██║   ██║      ██║   ██║         ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║
    ╚═╝╚═╝  ╚═══╝    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝         ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝
                                                                                                               
                                                                                                 \n\n"""+Style.RESET_ALL)
                infoHTTP.httpInfo() #redirecting to FTP server Check Tool
                SecondaryOption(3)
            elif optionS==3:
                actionCall("\n\nCalling Function To Scan For Sensitive Server Information Disclosure")
                print(Fore.RED+Style.DIM+"""
        ███████╗███████╗███╗   ██╗███████╗██╗████████╗██╗██╗   ██╗███████╗    ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗
        ██╔════╝██╔════╝████╗  ██║██╔════╝██║╚══██╔══╝██║██║   ██║██╔════╝    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
        ███████╗█████╗  ██╔██╗ ██║███████╗██║   ██║   ██║██║   ██║█████╗      ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
        ╚════██║██╔══╝  ██║╚██╗██║╚════██║██║   ██║   ██║╚██╗ ██╔╝██╔══╝      ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
        ███████║███████╗██║ ╚████║███████║██║   ██║   ██║ ╚████╔╝ ███████╗    ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
        ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═══╝  ╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

                    ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
                    ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
                    ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
                    ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
                    ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
                    ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  \n\n"""+Style.RESET_ALL)
                serverInfoTool.serverInfo() #Redirecting to server Information Detection Tool
                SecondaryOption(3)
            elif optionS==4:
                actionCall("\n\nCalling Function To Check For Important Security Headers")
                print(Fore.RED+Style.DIM+"""
                        ██╗███╗   ███╗██████╗  ██████╗ ██████╗ ████████╗ █████╗ ███╗   ██╗████████╗
                        ██║████╗ ████║██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗████╗  ██║╚══██╔══╝
                        ██║██╔████╔██║██████╔╝██║   ██║██████╔╝   ██║   ███████║██╔██╗ ██║   ██║
                        ██║██║╚██╔╝██║██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══██║██║╚██╗██║   ██║
                        ██║██║ ╚═╝ ██║██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║██║ ╚████║   ██║
                        ╚═╝╚═╝     ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝
                                                                                                                          
    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗    ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗
    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝    ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
    ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝     ███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗
    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝      ██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║
    ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║       ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║
    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝       ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝
\n\n"""+Style.RESET_ALL)
                impHeaders.impHeaderInfo() #Redirecting to X-XSS Protection Value Detection Tool
                SecondaryOption(3)
            elif optionS==5:
                actionCall("\n\nCalling Function To Check For Protection Against XSRF")
                print(Fore.RED+Style.DIM+"""
         ██████╗███████╗██████╗ ███████╗    ██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗
        ██╔════╝██╔════╝██╔══██╗██╔════╝    ██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
        ██║     ███████╗██████╔╝█████╗      ██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║
        ██║     ╚════██║██╔══██╗██╔══╝      ██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║
        ╚██████╗███████║██║  ██║██║         ██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║
        ╚═════╝╚══════╝╚═╝  ╚═╝╚═╝         ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                                                                     
                                              ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
                                             ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
                                             ██║     ███████║█████╗  ██║     █████╔╝
                                             ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗
                                             ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
                                              ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
\n\n"""+Style.RESET_ALL)                                                                                                                   
                xsrfCheck.xsrfInfo() #Redirecting to X-XSS Protection Value Detection Tool
                SecondaryOption(3)
            elif optionS==6:
                print("Going Back To PrimaryOptions.")
                PrimaryOptions()
            elif optionS==7:
                print(Fore.WHITE+"\n[.] You Have Called To Terminate The Program")
                actionCall("Terminating Execution")
                sys.exit() #Exit Program
            else:
                print(Fore.RED+Style.DIM+"Invalid choice! Do it again"+Style.RESET_ALL)
                time.sleep(0.5)
                SecondaryOption(3)
        except(Exception):
            print(Fore.RED+Style.RED+"Input of inavlid type entered. Enter Again"+Style.RESET_ALL)
            time.sleep(0.5)
            SecondaryOption(3)

try :
    fetchIndex()
except KeyboardInterrupt : #Handle Keyboard Interruption for the entire program.
    print(Fore.RED+Style.DIM+"\n\nYou pressed ctrl+C to interrupt the Execution in middle"+Style.RESET_ALL)
    actionCall("Terminating Execution")
    sys.exit()
