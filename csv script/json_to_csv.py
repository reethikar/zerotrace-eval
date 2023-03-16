import os
import pandas as pd
from datetime import datetime

filename = 'logFileoutput' + datetime.now().strftime("%Y_%m_%d-%I_%M_%S") + '.csv'
jsonObj = pd.read_json(path_or_buf=os.path.abspath('logFile.jsonl'), lines=True)
jsonObj = jsonObj.groupby('UUID',as_index=False,sort=False).last()
jsonObj['UUID'] = 'https://test.reethika.info/ping?uuid=' + jsonObj['UUID']
jsonObj = jsonObj.rename(columns={'Contact': 'Experiment Performed by', 'ExpType': 'Type of Connection (Direct via Wifi/Direct via Mobile Data/VPN)', 'Network': 'What WiFi/Mobile Data Was Used', 
                        'VPNprovider': 'VPN Provider', 'LocationVPN': 'VPN Location', 'LocationUser': 'User Location', 'IPaddr': 'IP'})
jsonObj.to_csv(os.path.abspath(filename), index=False)