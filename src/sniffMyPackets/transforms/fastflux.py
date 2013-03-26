#!/usr/bin/env python

import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.entities import Website
from canari.maltego.message import Field, Label
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
    label='Check for FastFlux [pcap]',
    description='Checks a pcap file and looks for fastflux domains',
    uuids=[ 'sniffMyPackets.v2.check4fastflux' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
	
  pcap = request.value
  dnsresp = []
  dnsip = []
  pkts = rdpcap(pcap)
  
  for pkt in pkts:
	if pkt.haslayer(DNSRR):
	  rrname = pkt.getlayer(DNSRR).rrname
	  rdata = pkt.getlayer(DNSRR).rdata
	  dnsreq = rrname, rdata
	  if rdata not in dnsresp:
		dnsresp.append(dnsreq)
	
 
 
 
  for domain, ip in dnsresp:
	print domain, ip
	  
  
	  #e = Website(item)
	  #e.linklabel = 'Unique IPs:\n' + str(x)
	  #e.linkcolor = 0x9933FF
	  #response += e
  #return response