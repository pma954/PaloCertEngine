from secrets import choice
from typing_extensions import Self
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


class CLI_Tools:
    def __init__(self, Username, Password):
        self.username = Username
        self.Password = Password


    def CheckForPrompt(prompt,StdOut):
        if prompt in StdOut:
            return True
        else:
            return False

    def GenerateCSR(FWName,username,password):
        CSRCommand="request certificate generate signed-by external filename "+FWName+" certificate-name "+FWName+" name "+FWName+".sherwin.com algorithm RSA rsa-nbits 2048"
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        client.connect(hostname=FWName+".sherwin.com", username=username, password=password, timeout = 50)
        x = client.invoke_shell()
        Ready = CLI_Tools.CheckForPrompt("admin@",x.recv(65535).decode('UTF-8'))
        while Ready != True:
            time.sleep(5)
            Ready = CLI_Tools.CheckForPrompt("admin@",x.recv(65535).decode('UTF-8'))
        if Ready:
            x.send(CSRCommand)
            time.sleep(3)
            x.send("\r")
            Ready = CLI_Tools.CheckForPrompt("Successfully generated certificate",x.recv(65535).decode('UTF-8'))
            while Ready != True:
                time.sleep(5)
                Ready = CLI_Tools.CheckForPrompt("Successfully generated certificate",x.recv(65535).decode('UTF-8'))
            if Ready:
                print("CSR Generated for "+FWName)
                print("Commit in Progress")
                Commit(FWName)

    def ExportCSR(FWName,username,password):
        #SRCommand="request certificate generate signed-by external filename "+FWName+" certificate-name "+FWName+" name "+FWName+".sherwin.com algorithm RSA rsa-nbits 2048"
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        client.connect(hostname=FWName+".sherwin.com", username=username, password=password, timeout = 50)
        x = client.invoke_shell()
        Ready = CLI_Tools.CheckForPrompt("admin@",x.recv(65535).decode('UTF-8'))
        while Ready != True:
            time.sleep(5)
            Ready = CLI_Tools.CheckForPrompt("admin@",x.recv(65535).decode('UTF-8'))
        if Ready:
            x.send("set cli pager off")
            time.sleep(3)
            x.send("\r")
            x.send("show config candidate")
            time.sleep(3)
            x.send("\r")
            Response=x.recv(65535).decode('UTF-8')
            Ready = CLI_Tools.CheckForPrompt("csr",Response)
            while Ready != True:
                time.sleep(5)
                Response=x.recv(65535).decode('UTF-8')
                Ready = CLI_Tools.CheckForPrompt("csr",Response)
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

    def AssignAndCommitCert(FWName,username,password):
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

    def GetCertInfo(FWName,username,password):
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        client.connect(hostname=FWName+".sherwin.com", username=username, password=password, timeout = 50)
        x = client.invoke_shell()
        Ready = CLI_Tools.CheckForPrompt("admin@",x.recv(65535).decode('UTF-8'))
        while Ready != True:
            time.sleep(5)
            Ready = CLI_Tools.CheckForPrompt("admin@",x.recv(65535).decode('UTF-8'))
        if Ready:
            x.send("request certificate show certificate-name "+FWName+"\r")
        Response = x.recv(65535).decode('UTF-8')
        Ready=CLI_Tools.CheckForPrompt("common-name",Response)
        while Ready != True:
            time.sleep(5)
            Response = x.recv(65535).decode('UTF-8')
            Ready = CLI_Tools.CheckForPrompt("common-name",Response)
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

class API_Tools:
    def __init__(self, Username, Password):
        self.username = Username
        self.password = Password

    def auth(self,FWName):
        url = "https://"+FWName+".sherwin.com/api/?type=keygen"
        payload={"user":self.username,
                    "password":self.password}
        headers = {}
        response = requests.request("POST", url,verify=False, headers=headers, data=payload)
        response=response.content.decode('utf-8')
        try:
            key = re.findall("(?<=<key>)(.*?)(?=</key>)", response)
            key=key[0]
        except:
            print("\nUnable to retrieve API Key. \nPlease Check your username and password")
        return str(key)
    
    def ImportCertificate(FWName):
        Key=API_Tools.auth(FWName)
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
            CLI_Tools.AssignAndCommitCert(FWName)
            return("Success")
        else:
            return("Failed")

    def Commit(self,FWName):
        Key=self.auth(self,FWName)
        response = requests.post("https://"+FWName+".sherwin.com/api/?key="+Key+"&type=commit&cmd=<commit></commit>",  verify=False)
        if str(response.status_code)==200:
            print("Commit in Progress")


