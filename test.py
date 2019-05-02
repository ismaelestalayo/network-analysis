from scapy.all import *
from collections import Counter

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd
import seaborn as sns
sns.set_color_codes("pastel")
sns.set(style="darkgrid")


# #######################################################################
# import Wireshark capture
packets = rdpcap('dump.pcapng')


# #######################################################################
# make list for IPv4 and IPv6 packets
packetsV4 = []
packetsV6 = []
for p in packets:
	if( p.type == 0x800):		# IPv4 packets
		packetsV4.append(p)
		
	elif( p.type == 0x86dd):	# IPv6 packets
		packetsV6.append(p)

print("2048: IPv4, 34525: IPv6")
Counter([x.type for x in packets])


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
gf=nx.Graph()

for index, d in df4.iterrows():
	gf.add_edge( d['MAC_src'], d['MAC_dst'] )

nx.draw_networkx(gf)
plt.tight_layout()
plt.axis('off')
plt.show()

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

