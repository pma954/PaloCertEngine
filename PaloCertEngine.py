from secrets import choice
import paramiko
import time
import getpass
import requests
import getpass
import pandas as pd
import re
import os
import ssl
import xmltodict
from pyfiglet import Figlet

ssl._create_default_https_context = ssl._create_unverified_context
requests.packages.urllib3.disable_warnings()


path = os.path.join(os.getcwd(), os.path.dirname(__file__))

def CheckForPrompt(prompt,StdOut):
    if prompt in StdOut:
        return True
    else:
        return False

def auth(FWName):
    url = "https://"+FWName+".sherwin.com/api/?type=keygen"
    payload={"user":username,
                "password":password}
    headers = {}
    response = requests.request("POST", url,verify=False, headers=headers, data=payload)
    response=response.content.decode('utf-8')
    try:
        key = re.findall("(?<=<key>)(.*?)(?=</key>)", response)
        key=key[0]
    except:
        print("\nUnable to retrieve API Key. \nPlease Check your username and password")
    return str(key)

def GenerateCSR(FWName):
    CSRCommand="request certificate generate signed-by external filename "+FWName+" certificate-name "+FWName+" name "+FWName+".sherwin.com algorithm RSA rsa-nbits 2048"
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    client.connect(hostname=FWName+".sherwin.com", username=username, password=password, timeout = 50)
    x = client.invoke_shell()
    Ready = CheckForPrompt("admin@",x.recv(65535).decode('UTF-8'))
    while Ready != True:
        time.sleep(5)
        Ready = CheckForPrompt("admin@",x.recv(65535).decode('UTF-8'))
    if Ready:
        x.send(CSRCommand)
        time.sleep(3)
        x.send("\r")
        Ready = CheckForPrompt("Successfully generated certificate",x.recv(65535).decode('UTF-8'))
        while Ready != True:
            time.sleep(5)
            Ready = CheckForPrompt("Successfully generated certificate",x.recv(65535).decode('UTF-8'))
        if Ready:
            print("CSR Generated for "+FWName)
            print("Commit in Progress")
            Commit(FWName)

def ExportCSR(FWName):
    #SRCommand="request certificate generate signed-by external filename "+FWName+" certificate-name "+FWName+" name "+FWName+".sherwin.com algorithm RSA rsa-nbits 2048"
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    client.connect(hostname=FWName+".sherwin.com", username=username, password=password, timeout = 50)
    x = client.invoke_shell()
    Ready = CheckForPrompt("admin@",x.recv(65535).decode('UTF-8'))
    while Ready != True:
        time.sleep(5)
        Ready = CheckForPrompt("admin@",x.recv(65535).decode('UTF-8'))
    if Ready:
        x.send("set cli pager off")
        time.sleep(3)
        x.send("\r")
        x.send("show config candidate")
        time.sleep(3)
        x.send("\r")
        Response=x.recv(65535).decode('UTF-8')
        Ready = CheckForPrompt("csr",Response)
        while Ready != True:
            time.sleep(5)
            Response=x.recv(65535).decode('UTF-8')
            Ready = CheckForPrompt("csr",Response)
        if Ready:
            csr=re.findall(r"(?s)(?<=csr \")(.*?)(?=\n\";)", Response)
            with open(os.path.join(path+"\\"+FWName+".txt"), "w", newline='\n') as text_file:
                text_file.write(str(csr[0]).strip())
            print(csr[0])
            client.close()
            WINDOWS_LINE_ENDING = b'\r\n'
            UNIX_LINE_ENDING = b'\n'
            with open(os.path.join(path+"\\"+FWName+".txt"), 'rb') as open_file:
                content = open_file.read()
            content = content.replace(WINDOWS_LINE_ENDING, UNIX_LINE_ENDING)
            with open(os.path.join(path+"\\"+FWName+".txt"), 'wb') as open_file:
                open_file.write(content)


def ImportCertificate(FWName):
    Key=auth(FWName)
    params = {
    'key': Key,
    'type': 'import',
    'category': 'certificate',
    'certificate-name': FWName,
    'format': 'pem',
    }
    files = {
        'file': open(os.path.join(path+"\\"+FWName+".sherwin.com.cer"), 'rb'),
    }
    response = requests.post("https://"+FWName+".sherwin.com/api/", params=params, files=files,verify=False)
    if str(response.status_code)==200:
        print("\n\nSuccessfully Imported Certificate.\n\nCommitting new Certificate")
        AssignAndCommitCert(x)
        return("Success")
    else:
        return("Failed")

def Commit(FWName):
    Key=auth(FWName)
    response = requests.post("https://"+FWName+".sherwin.com/api/?key="+Key+"&type=commit&cmd=<commit></commit>",  verify=False)
    if str(response.status_code)==200:
        print("Commit in Progress")

def AssignAndCommitCert(FWName):
    print("Assigning new Certificate to SSL profile")
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    client.connect(hostname=FWName+".sherwin.com", username=username, password=password, timeout = 50)
    x = client.invoke_shell()
    while "admin@" not in x.recv(65535).decode('UTF-8'):
        time.sleep(5)
    x.send("configure\r")
    while "[edit]" not in x.recv(65535).decode('UTF-8'):
        time.sleep(5)
    x.send("set shared ssl-tls-service-profile SignedCert certificate "+FWName+" protocol-settings min-version tls1-0 max-version max\r")
    time.sleep(5)
    x.send("set deviceconfig system ssl-tls-service-profile SignedCert\r")
    time.sleep(5)
    x.send("commit\r")
    time.sleep(5)
    client.close()   

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

def GetCertInfo(FWName):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    client.connect(hostname=FWName+".sherwin.com", username=username, password=password, timeout = 50)
    x = client.invoke_shell()
    Ready = CheckForPrompt("admin@",x.recv(65535).decode('UTF-8'))
    while Ready != True:
        time.sleep(5)
        Ready = CheckForPrompt("admin@",x.recv(65535).decode('UTF-8'))
    if Ready:
        x.send("request certificate show certificate-name "+FWName+"\r")
    Response = x.recv(65535).decode('UTF-8')
    Ready=CheckForPrompt("common-name",Response)
    while Ready != True:
        time.sleep(5)
        Response = x.recv(65535).decode('UTF-8')
        Ready = CheckForPrompt("common-name",Response)
        if "admin@" in Response:
            break
    if Ready:
        CommonName=re.findall(r"(?<=common-name: )(.*?)(?=\n)",Response)[0]
        ValidFrom=re.findall(r"(?<=not-valid-before )(.*?)(?=GMT)",Response)[0]
        ValidFrom=re.sub("([1-9]{2}:(.*?)(?= ))","",ValidFrom)
        ValidTo=re.findall(r"(?<=not-valid-after )(.*?)(?=GMT)",Response)[0]
        ValidTo=re.sub("([1-9]{2}:(.*?)(?= ))","",ValidTo)
    else:
        CommonName="No Cert"
        ValidFrom="No Cert"
        ValidTo="No Cert"
    data={'Firewall':FWName,'CommonName':CommonName,'ValidFrom':ValidFrom,'ValidTo':ValidTo}
    df=pd.DataFrame(data,index=[0])
    ExistingData=pd.read_csv(os.path.join(path+"\\ICS_FW_Cert_Info.csv"))
    NewData=ExistingData.append(df, ignore_index=True)
    NewData=NewData.drop_duplicates()
    NewData.to_csv(os.path.join(path+"\\ICS_FW_Cert_Info.csv"),index=False)


def showKnownFWs():
    AllFirewalls=pd.read_csv(os.path.join(path+"\\ICS_FW_Cert_Info.csv"))
    AllFirewalls=AllFirewalls['Firewall'].to_list()
    print(AllFirewalls)
        
def UpdateKnownFWs():
    PanKey=auth("panorama")
    response = requests.get('https://panorama.sherwin.com/api/?key='+PanKey+'&type=op&cmd=<show><devices><all></all></devices></show>',verify=False)
    AllDeviceDict=xmltodict.parse(response.content)
    if str(response.status_code)!="200":
        print("Failed to auth to panorama")
        return("")
    AllFirewalls=re.findall(r"(?<='hostname': )(.*?)(?=,)",str(AllDeviceDict))
    ICSFirewalls=[]
    for x in AllFirewalls:
        if 'icsfw' in str(x):
            x=str(x).replace("'","")
            ICSFirewalls.append(str(x))
    KnownFirewallinfo=pd.read_csv(os.path.join(path+"\\ICS_FW_Cert_Info.csv"))
    KnownFirewalls=KnownFirewallinfo['Firewall'].to_list()
    for x in ICSFirewalls:
        if x not in KnownFirewalls:
            FWName=str(x).strip()
            CommonName="unknown"
            ValidFrom="unknown"
            ValidTo="unknown"
            data={'Firewall':FWName,'CommonName':CommonName,'ValidFrom':ValidFrom,'ValidTo':ValidTo}
            df=pd.DataFrame(data,index=[0])
            print(df)
            KnownFirewallinfo=pd.concat([KnownFirewallinfo,df], ignore_index=True)
    KnownFirewallinfo.to_csv(os.path.join(path+"\\ICS_FW_Cert_Info.csv"),index=False)

def UpdateinfoForKnownFirewalls():
    KnownFirewallinfo=pd.read_csv(os.path.join(path+"\\ICS_FW_Cert_Info.csv"))
    UnknownCertInfo=KnownFirewallinfo[KnownFirewallinfo['CommonName']=="unknown"]
    UnknownFWs=UnknownCertInfo['Firewall'].to_list()
    for x in UnknownFWs:
        print("Gathering info for "+x)
        GetCertInfo(x)
    df=pd.read_csv(os.path.join(path+"\\ICS_FW_Cert_Info.csv"))
    df['CommonName'] = df['CommonName'].str.replace(r'\n', '')
    df['CommonName'] = df['CommonName'].str.replace(r'\r', '')
    NowKnown=df[df['CommonName']!="unknown"]
    KnownList=NowKnown['Firewall'].tolist()
    UnKnown=df[df['CommonName']=="unknown"]
    UnKnown=UnKnown[~UnKnown['Firewall'].isin(KnownList)]
    df=pd.concat([UnKnown,NowKnown], ignore_index=True)
    df.to_csv(os.path.join(path+"\\ICS_FW_Cert_Info.csv"),index=False)
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
Choice=""

while Choice != "exit":
    Choice=DisplayOptions()
    if Choice == "1":
        print("\nGenerate CSR for Firewall\n")
        FWList = input("\nPlease enter desired Firewalls separated by commas (uswmpicsfwa,uswmpicsfwb,etc.)\n\nEnter Here: ")
        username= 'admin'
        password =getpass.getpass("please enter the password for 'admin': ")
    elif Choice == "2":
        print("\nImport Signed Certificates to Firewalls\n")
        FWList = input("\nPlease enter desired Firewalls separated by commas (uswmpicsfwa,uswmpicsfwb,etc.)\n\nEnter Here: ")
        username= 'admin'
        password =getpass.getpass("please enter the password for 'admin': ")   
    elif Choice == "3":
        print("\nCheck Certificate Status on Firewall(s)\n")
        FWList = input("\nPlease enter desired Firewalls separated by commas (uswmpicsfwa,uswmpicsfwb,etc.)\n\nEnter Here: ")
        username= 'admin'
        password =getpass.getpass("please enter the password for 'admin': ")   
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
        UpdateKnownFWs()
    else:
        print("\nThat wasn't a choice. Try Again.\n")
    pause="~"
    while pause=="~":
        time.sleep(1)
        pause=input()

