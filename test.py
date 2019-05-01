from scapy.all import *
from collections import Counter

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd

packets = rdpcap('dump.pcapng')

#Lists to hold packet info
pktBytes=[]


pktTimes=[]
pktList = []

# Let's iterate through every packet
for pkt in packets:
    if IP in pkt:
        pktList.append( pkt )
        # pktBytes.append( pkt[IP].len )
        pktTimes.append( datetime.fromtimestamp(pkt.time).strftime("%Y-%m-%d %H:%M:%S.%f") )

bytes = pd.Series(pktBytes).astype(int)
times = pd.to_datetime(pd.Series(pktTimes).astype(str),  errors='coerce')

#Create the dataframe
df = pd.DataFrame({"Bytes": bytes, "Times":times})
df = df.set_index('Times')

#Create a new dataframe of 2 second sums to pass to plotly
df2=df.resample('2S').sum()
# print(df2)

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
			'L3':		p[3].name
		} )
	except:
		k4.append({	
			'MAC_src': 	p.src, 
			'MAC_dst': 	p.dst, 
			'IP_src': 	p[1].src, 
			'IP_dst': 	p[1].dst,
			'L2': 		p[2].name,
			'L3':		'NULL'
		} )
	
k6 = [{	'MAC_src': 	p.src, 
		'MAC_dst': 	p.dst, 
		'IP_src': 	p[1].src, 
		'IP_dst': 	p[1].dst,
		'L2': 		p[2].name
		# 'L3':		p[3].name
	} for p in packetsV6]

df4 = pd.DataFrame(k4)
df6 = pd.DataFrame(k6)

# #######################################################################
# create and plot undirected graph
gf=nx.Graph()

for index, d in df4.iterrows():
	gf.add_edge( d['MAC_src'], d['MAC_dst'] )

nx.draw_networkx(gf)
plt.tight_layout()
plt.axis('off')
plt.show()