import requests
import pandas as pd
import re
import os
import xmltodict
path = os.path.join(os.getcwd(), os.path.dirname(__file__))

class Authentication:
    def auth(FWName,username,password):
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

class PullInformation:
    def UpdateKnownFWs():
        PanKey=Authentication.auth("panorama")
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