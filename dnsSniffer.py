#!/usr/bin/python

from scapy.all import DNSQR, DNSRR, UDP, IP, DNS, sniff
from datetime import datetime

INTERFACE = "eth0" # change to your sniffing interface
# number of sniffed queries, don't forget that for every query there is a response. Uncomment if you want to specify the number of DNS packets
# NUMBER_QUERIES = 10

def grep_DNS_queries(packet):
	packet_time = packet.sprintf('%sent.time%')

	try:
		if DNSQR in packet and packet.dport == 53:
			
			print packet[DNS].summary() + '\n[' + packet[IP].src + '] -> [' + packet[IP].dst + '] at [' + packet_time + ']'

		elif DNSRR in packet and packet.sport == 53:
			
			print packet[DNS].summary() + '\n['+ packet[IP].src + '] -> [' + packet[IP].dst + '] at [' + packet_time + ']'

	except:
		pass
			
# sniffs the packets
packets = sniff(iface = INTERFACE, filter = "udp and port 53", store = 0, prn = grep_DNS_queries)#, count = NUMBER_QUERIES)
