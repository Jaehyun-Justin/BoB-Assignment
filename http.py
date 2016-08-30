import time
from scapy.all import *
import copy

lm = lambda n: "x" * n
st = False
def Filter_handle(packet):
	global st
	packet.show()
	eth = packet[Ether]
	ip = packet[IP]
	tcp = packet[TCP]
	packet4 = copy.deepcopy(packet)
	ethn = packet4[Ether]
	ipn = packet4[IP]
	tcpn = packet4[TCP]
	ethn.dst = eth.src;
	ethn.src = eth.dst;
	ipn.dst = ip.src;
	ipn.src = ip.dst;
	tcpn.seq = tcp.ack
	tcpn.ack = tcp.seq + len(tcp.load)
	tcpn.sport = tcp.dport
	tcpn.dport = tcp.sport
	del tcpn.load
	tcpn.load = "HTTP/1.1 302 Found \r\nLocation: https://en.wikipedia.org/wiki/HTTP_302"
	PacketToServer = packet4
	del PacketToServer[IP].chksum
	del PacketToServer[IP].len
	del PacketToServer[TCP].chksum
	PacketToServer.show2()
	sendp(PacketToServer)
	packet2 = copy.deepcopy(packet)
	Eth_h1 = packet2[Ether]
	IP_h1 = packet2[IP]
	TCP_h1 = packet2[TCP]
	TCP_h1.load = "blocked\r\n"
	TCP_h1.seq += len(tcp.load)
	PacketToServer = packet2
	del PacketToServer[IP].chksum
	del PacketToServer[IP].len
	del PacketToServer[TCP].chksum
	PacketToServer.show2()
	sendp(PacketToServer)
	st = True;
	del packet
	return
def stopfilter(x):
	global st
	if st == True:
		return True
	else:
		return False

sniff(iface='ens33', prn=Filter_handle, lfilter=lambda p: "GET" in str(p), filter="tcp port 80", store=0)
