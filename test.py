from scapy.all import *
from collections import Counter

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd
import requests
import seaborn as sns
sns.set_color_codes("pastel")
sns.set(style="darkgrid")
pd.set_option('display.max_columns', 20)


# #######################################################################
# FingerBank (DHCP fingerprint)     https://api.fingerbank.org/api/v2/combinations/interrogate?dhcp_fingerprint=1,3,6,15,26,28,51,58,59,43&key=44b937bf195d9e5f596f13cc494526b5da633316
key='44b937bf195d9e5f596f13cc494526b5da633316'
def fingerbank_DHCP_fingerprint(fingerprint):
	URL = 'https://api.fingerbank.org/api/v2/combinations/interrogate?dhcp_fingerprint='+fingerprint+'&key='+key
	r = requests.get(url = URL) 
	print("RESPONSE:", r.status_code, '\n')
	if(r.status_code == 200):
		print( r.json(), '\n')
		print( r.json()['device']['name'] )
	
	return r

# #######################################################################
# import Wireshark capture
packets = rdpcap('dump_uni.pcapng')


# #######################################################################
# make list for IPv4 and IPv6 packets
packetsV4 = []
packetsV6 = []
for p in packets:
	if( p.type == 0x800):		# IPv4 packets 2048
		packetsV4.append(p)
		
	elif( p.type == 0x86dd):	# IPv6 packets 34525
		packetsV6.append(p)


k4 = []
for p in packetsV4:
	try:
		k4.append({	
			'MAC_src': 	p.src, 
			'MAC_dst': 	p.dst, 
			'IP_src': 	p[1].src, 
			'IP_dst': 	p[1].dst,
			'L2': 		p[2].name,
			'L3':		p[3].name,
			'port_src':	p[2].sport,
			'port_dst':	p[2].dport
		} )
	except:
		k4.append({	
			'MAC_src': 	p.src, 
			'MAC_dst': 	p.dst, 
			'IP_src': 	p[1].src, 
			'IP_dst': 	p[1].dst,
			'L2': 		p[2].name,
			'L3':		'NULL',
			'port_src':	p[2].sport,
			'port_dst':	p[2].dport
		} )
	
k6 = [{	'MAC_src': 	p.src, 
		'MAC_dst': 	p.dst, 
		'IP_src': 	p[1].src, 
		'IP_dst': 	p[1].dst,
		'L2': 		p[2].name,
		'L3':		p[3].name
	} for p in packetsV6]

df4 = pd.DataFrame(k4)
df6 = pd.DataFrame(k6)

# #######################################################################
# undirected graph of connections
# gf=nx.Graph()

# for index, d in df4.iterrows():
# 	gf.add_edge( d['MAC_src'], d['MAC_dst'] )

# nx.draw_networkx(gf)
# plt.tight_layout()
# plt.axis('off')
# plt.show()

# #######################################################################
# histogram of source and destination ports
plt.subplot(2, 1, 1)
plt.title('port_src')
sns.barplot(x=list( Counter(df4['port_src']).keys() ), y=list( Counter(df4['port_src']).values() ) )
sns.despine()
plt.subplot(2, 1, 2)
plt.title('port_dst')
sns.barplot(x=list( Counter(df4['port_dst']).keys() ), y=list( Counter(df4['port_dst']).values() ) )
sns.despine()
plt.tight_layout()
plt.show()
# plt.subplots_adjust(left=0.1, bottom=0.05, right=0.95, top=0.95, wspace=0.2, hspace=0.3)

# histogram of source and destination IPs
plt.subplot(2, 1, 1)
plt.title('IP_src')
sns.barplot(x=list( Counter(df4['IP_src']).values() ), y=list( Counter(df4['IP_src']).keys() ) )
sns.despine()
plt.subplot(2, 1, 2)
plt.title('IP_dst')
sns.barplot(x=list( Counter(df4['IP_dst']).values() ), y=list( Counter(df4['IP_dst']).keys() ) )
sns.despine()
plt.tight_layout()
plt.show()


# list of packet numbers with DHCP
dhcp = df4[ df4['L3']=='BOOTP']
dhcp = [i for i, d in dhcp.iterrows()]

info = []
for d in dhcp:
	p = packetsV4[ d ][4].options	# 4th layer, DHCP, has an 'options' field
	info.append( dict(p[:-1]) )

kk = pd.DataFrame( info )
fingerprint = str(", ").join(str(x) for x in kk.iloc[0]['param_req_list'] ).replace(" ", "")
r = fingerbank_DHCP_fingerprint(fingerprint)
