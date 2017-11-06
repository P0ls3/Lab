#!/usr/bin/python

from scapy.all import *
import netaddr

r = raw_input("Type netwrok range (ex- 172.16.20.0/24): ")
network = r

addr = netaddr.IPNetwork(network)
liveCounter = 0

for host in addr:
	if (host == addr.network or host == addr.broadcast):
		continue
	resp = sr1(IP(dst=str(host))/ICMP(),timeout=2,verbose=0)
	if (str(type(resp)) == "<type 'NoneType'>"):
		print str(host) + " is down or not responding."
	elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
	        print str(host) + " is blocking ICMP."
	else:
		print str(host) + " is responding."
		liveCounter += 1

print "Out of " + str(addr.size) + " hosts, " + str(liveCounter) + " are online."
