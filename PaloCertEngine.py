import time
import getpass
import requests
import getpass
import pandas as pd
import os
import ssl
from pyfiglet import Figlet
from hashlib import sha256
from Dependencies.PanoramaAPI import PullInformation
from Dependencies.PaloFWCertTools import CLI_Tools
from Dependencies.PaloFWCertTools import API_Tools


ssl._create_default_https_context = ssl._create_unverified_context
requests.packages.urllib3.disable_warnings()

path = os.path.join(os.getcwd(), os.path.dirname(__file__))

def convertCertificate(FWName):
    print("Converting Cert to Base64 encoding")
    with open(os.path.join(path+"\\"+FWName+".sherwin.com.cer"), 'rb') as open_file:          
        CertBytes=open_file.read()
        cert_PEM = ssl.DER_cert_to_PEM_cert(CertBytes)
        with open(os.path.join(path+"\\"+FWName+".sherwin.com.cer"), 'w') as open_file:
            open_file.write(cert_PEM)
        WINDOWS_LINE_ENDING = b'\r\n'
        UNIX_LINE_ENDING = b'\n'
        with open(os.path.join(path+"\\"+FWName+".sherwin.com.cer"), 'rb') as open_file:
            content = open_file.read()
        content = content.replace(WINDOWS_LINE_ENDING, UNIX_LINE_ENDING)
        with open(os.path.join(path+"\\"+FWName+".sherwin.com.cer"), 'wb') as open_file:
            open_file.write(content)


def showKnownFWs():
    AllFirewalls=pd.read_csv(os.path.join(path+"\\ICS_FW_Cert_Info.csv"))
    AllFirewalls=AllFirewalls['Firewall'].to_list()
    print(AllFirewalls)
        

def UpdateinfoForKnownFirewalls():
    KnownFirewallinfo=pd.read_csv(os.path.join(path+"\\ICS_FW_Cert_Info.csv"))
    UnknownCertInfo=KnownFirewallinfo[KnownFirewallinfo['CommonName']=="unknown"]
    UnknownFWs=UnknownCertInfo['Firewall'].to_list()
    for x in UnknownFWs:
        print("Gathering info for "+x)
        FWCLI.GetCertInfo(x)
    df=pd.read_csv(os.path.join(path+"\\ICS_FW_Cert_Info.csv"))
    df['CommonName'] = df['CommonName'].str.replace(r'\n', '')
    df['CommonName'] = df['CommonName'].str.replace(r'\r', '')
    NowKnown=df[df['CommonName']!="unknown"]
    KnownList=NowKnown['Firewall'].tolist()
    UnKnown=df[df['CommonName']=="unknown"]
    UnKnown=UnKnown[~UnKnown['Firewall'].isin(KnownList)]
    df=pd.concat([UnKnown,NowKnown], ignore_index=True)
    df.to_csv(os.path.join(path+"/Dependencies/ICS_FW_Cert_Info.csv"),index=False)
    print(df)

def DisplayOptions():
    print("\n\n\n")
    print("Please Select from the following options:\n\n")
    print("1. Generate CSR for Firewall(s)\n")
    print("2. Import Signed Certificates to Firewalls\n")
    print("3. Check Certificate Status on Firewall(s)\n")
    print("4. Show Known Firewalls \n")
    print("5. Update cert info sheet for known firewalls with 'Unknown' Certs \n")
    print("6. Update Known Firewalls (Pulls list of ICS FWs from Panorama)")
    Selection = input("\nSelection [1-6] or exit: ")
    return(Selection)


WelcomeBanner = Figlet(font='slant')
print(WelcomeBanner.renderText('ICS FW'))
print(WelcomeBanner.renderText('Cert Manager'))
time.sleep(3)
username= 'admin'
hex_dig=""
while str(hex_dig) != "2815ed4ed09d1e9d9cb177780f7271acdeffba9360525debee90d76f2c0e1381":
    password = getpass.getpass("\n\nplease enter the Firewall Admin Password: ")
    hash_object = sha256(password.encode('utf-8'))
    hex_dig = hash_object.hexdigest()

FWAPI=API_Tools(username,password)
FWCLI=CLI_Tools(username,password)

Choice=""

while Choice != "exit":
    Choice=DisplayOptions()
    if Choice == "1":
        print("\nGenerate CSR for Firewall\n")
        FWList = input("\nPlease enter desired Firewalls separated by commas (uswmpicsfwa,uswmpicsfwb,etc.)\n\nEnter Here: ")
        for x in FWList:
            FWCLI.GenerateCSR(x)
            FWCLI.ExportCSR(x)

    elif Choice == "2":
        print("\nImport Signed Certificates to Firewalls\n")
        FWList = input("\nPlease enter desired Firewalls separated by commas (uswmpicsfwa,uswmpicsfwb,etc.)\n\nEnter Here: ")
        for x in FWList:
            FWAPI.ImportCertificate(x)
            FWCLI.AssignAndCommitCert(x)

    elif Choice == "3":
        print("\nCheck Certificate Status on Firewall(s)\n")
        FWList = input("\nPlease enter desired Firewalls separated by commas (uswmpicsfwa,uswmpicsfwb,etc.)\n\nEnter Here: ")
        for x in FWList:
            FWCLI.GetCertInfo(x,False)

    elif Choice == "4":
        print("\nShow Known Firewalls\n")
        showKnownFWs()
        print("\n\n")

    elif Choice =="5":
        print("\nUpdate cert info sheet for known firewalls with 'Unknown' Certs \n")
        print("\nThis will take around 2 minutes per firewall...\n")
        username= 'admin'
        password =getpass.getpass("please enter the password for 'admin': ") 
        UpdateinfoForKnownFirewalls()
        print("done")

    elif Choice =="6":
        print("\nUpdating Known Firewalls...\n")
        username= 'admin'
        password =getpass.getpass("please enter the password for 'admin': ") 
        PanInfo=PullInformation(username,password)
        PanInfo.UpdateKnownFWs()
    else:
        print("\nThat wasn't a choice. Try Again.\n")
    pause="~"
    while pause=="~":
        time.sleep(1)
        pause=input()

