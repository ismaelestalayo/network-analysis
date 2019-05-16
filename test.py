from scapy.all import *
from collections import Counter
from bs4 import BeautifulSoup

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd
import requests
import seaborn as sns
sns.set_color_codes("pastel")
sns.set(style="darkgrid")
pd.set_option('display.max_columns', 20)


key='44b937bf195d9e5f596f13cc494526b5da633316'

# ##################################################################################
def DHCP_fingerprint(fingerprint):
	""" Makes a request to FingerBank API """
	URL = 'https://api.fingerbank.org/api/v2/combinations/interrogate?dhcp_fingerprint='+fingerprint+'&key='+key
	r = requests.get(url = URL)

	if(r.status_code == 200):
		print( r.json()['device']['name'] )
	else:
		print('### Error on the FingerBank API request!')
		
	return r

# ##################################################################################
# Manufacturer according to OUI (Organizationally Unique Identifier)
def OUI_lookup(mac):
	""" Searchs a specified MAC on the OUI csv"""
	mac_oui = mac.upper().replace(':', '')[:6]
	return oui[ oui['Assignment'] == mac_oui ].iloc[0]['Organization Name']

# ##################################################################################
def filter_IPv4( packetsV4 ):
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

	return pd.DataFrame(k4)

# ##################################################################################
def filter_IPv6( packetsV6 ):
	k6 = [{	'MAC_src': 	p.src, 
			'MAC_dst': 	p.dst, 
			'IP_src': 	p[1].src, 
			'IP_dst': 	p[1].dst,
			'L2': 		p[2].name,
			'L3':		p[3].name
	} for p in packetsV6]

	return pd.DataFrame(k6)

# ##################################################################################
# import Wireshark capture and stuff
packets = rdpcap('dump_uni2.pcapng')
oui = pd.read_csv('oui.csv')

# make list for IPv4 and IPv6 packets
packetsV4 = []
packetsV6 = []
for p in packets:
	if( p.type == 0x800):		# IPv4 packets 2048
		packetsV4.append(p)
		
	elif( p.type == 0x86dd):	# IPv6 packets 34525
		packetsV6.append(p)

df4 = filter_IPv4( packetsV4 )
df6 = filter_IPv6( packetsV6 )

# ##################################################################################
# undirected graph of connections
# gf=nx.Graph()

# for index, d in df4.iterrows():
# 	gf.add_edge( d['MAC_src'], d['MAC_dst'] )

# nx.draw_networkx(gf)
# plt.tight_layout()
# plt.axis('off')
# plt.show()

# ##################################################################################
# histogram of source and destination ports
# plt.subplot(2, 1, 1)
# plt.title('port_src')
# sns.barplot(x=list( Counter(df4['port_src']).keys() ), y=list( Counter(df4['port_src']).values() ) )
# sns.despine()
# plt.subplot(2, 1, 2)
# plt.title('port_dst')
# sns.barplot(x=list( Counter(df4['port_dst']).keys() ), y=list( Counter(df4['port_dst']).values() ) )
# sns.despine()
# plt.tight_layout()
# plt.show()
# # plt.subplots_adjust(left=0.1, bottom=0.05, right=0.95, top=0.95, wspace=0.2, hspace=0.3)

# histogram of source and destination IPs
# plt.subplot(2, 1, 1)
# plt.title('IP_src')
# sns.barplot(x=list( Counter(df4['IP_src']).values() ), y=list( Counter(df4['IP_src']).keys() ) )
# sns.despine()
# plt.subplot(2, 1, 2)
# plt.title('IP_dst')
# sns.barplot(x=list( Counter(df4['IP_dst']).values() ), y=list( Counter(df4['IP_dst']).keys() ) )
# sns.despine()
# plt.tight_layout()
# plt.show()


# ##################################################################################
# list of packet numbers with DHCP
dhcp = [index for index, data in df4[ df4['L3']=='BOOTP'].iterrows()] 	# DHCP

# array = []
for i in dhcp:
	print('\nAnalyzing DHCP packet...')
	p = packetsV4[i][4].options		# 4th layer, DHCP, has an 'options' field
	end = p.index('end')			# find where it ends (cuz it may have 'pad' elements)
	pp = dict(p[:end])

	print('> Hostname: %s ' % pp['hostname'])
	try:
		print('> Vendor: %s' % pp['vendor_class_id'])
	except:
		print('> No vendor found ')
	
	mac = packetsV4[i].src
	print('> Searching MAC OUI manufacturer [%s]... ' % mac)
	OUI_lookup(mac)
	
	fingerprint = ",".join([str(x) for x in pp['param_req_list']])
	print('> Searching fingerprint [%s] ...' % fingerprint)
	r = DHCP_fingerprint(fingerprint)


# 	array.append( dict(p[:i]) )

# dhcp_df = pd.DataFrame( array )




# ##################################################################################
# list of packet numbers with DNS
dns = [index for index, data in df4[ df4['L3']=='DNS'].iterrows()]	# DNS
for i in dns:
	if  ( packetsV4[i][4].name == 'DNS Resource Record'):
		print("\n> DNS response (packet %d) " % i)
		print('   ', packetsV4[i][4].rdata )
		print('   ', packetsV4[i][4].rrname )
	
	elif( packetsV4[i][4].name == 'DNS Question Record'):
		# print("> DNS query (packet %d) " % i)
		pass


# 30074d

