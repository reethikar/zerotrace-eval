import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


df = pd.read_json(path_or_buf=os.path.abspath('logFile.jsonl'), lines=True)
df = df.groupby('UUID',as_index=False,sort=False).last()
df['UUID'] = 'https://test.reethika.info/ping?uuid=' + df['UUID']
df = df.rename(columns={'Contact': 'Experiment Performed by', 'ExpType': 'Type of Connection (Direct via Wifi/Direct via Mobile Data/VPN)', 'Network': 'What WiFi/Mobile Data Was Used', 
                        'VPNprovider': 'VPN Provider', 'LocationVPN': 'VPN Location', 'LocationUser': 'User Location', 'IPaddr': 'IP'})
df.index +=1

#removing values for direct connection by riyaag, recorded on the first few wrong runs of selenium script where the connection was actually through vpn
index1 = df[ (df['Experiment Performed by'] == 'riyaag') & (df['Type of Connection (Direct via Wifi/Direct via Mobile Data/VPN)'] == 'direct')].index
df.drop(index1 , inplace=True)
df = df.dropna(subset='MSSVal')
df = df[df['Type of Connection (Direct via Wifi/Direct via Mobile Data/VPN)'].notna()]

df_vpn = df[ (df['Type of Connection (Direct via Wifi/Direct via Mobile Data/VPN)'] == 'vpn')].apply(pd.Series)
df_dir = df[ (df['Type of Connection (Direct via Wifi/Direct via Mobile Data/VPN)'] == 'direct')].apply(pd.Series)

data_dir = df_dir['AppLayerRtt'] - df_dir[['NWLayerRttICMP', 'NWLayerRtt0T']].min(axis=1)
data_dir = data_dir.to_numpy()
data_dir = data_dir / 1000

data_vpn = np.zeros(df_vpn.shape[0])
i=0

for index, row in df_vpn.iterrows():
    if (row['AppLayerRtt'] - row['NWLayerRttTCP'])/1000 > 40:
        data_vpn[i] = row['AppLayerRtt'] - min(row['NWLayerRttICMP'], row['NWLayerRtt0T'])
    else:
        data_vpn[i] = abs(min(row['AppLayerRtt'], row['NWLayerRttTCP']) - min(row['NWLayerRttICMP'], row['NWLayerRtt0T']))
    i = i+1

data_vpn = data_vpn[data_vpn<60000]
data_vpn = data_vpn / 1000

fig, ax = plt.subplots()

n1, x1, _  = plt.hist(data_vpn, bins=10, density=True, cumulative=True, histtype='step')
n2, x2, _  = plt.hist(data_dir, bins=10, density=True, cumulative=True, histtype='step')
plt.clf()
bin_centers1 = 0.5*(x1[1:]+x1[:-1])
bin_centers2 = 0.5*(x2[1:]+x2[:-1])
plt.plot(bin_centers1,n1,'r', label='VPN Connection')
plt.plot(bin_centers2,n2,'b', label='Direct Connection')

plt.xlabel('Difference in RTT in ms')
plt.ylabel('Proportion of Experiments')
plt.legend()
plt.show()
