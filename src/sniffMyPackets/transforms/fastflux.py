#!/usr/bin/env python

import os, sys
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
	
  pkts = rdpcap(request.value)
  dnsDict = {}
  dnsCount = {}
  
  for pkt in pkts:
	if pkt.haslayer(DNSRR):
	  rrname = pkt.getlayer(DNSQR).qname
	  rdata = pkt.getlayer(DNSRR).rdata
	  if rrname in dnsDict:
		rlist = dnsDict[rrname]
		if (rlist):
		  if (rdata not in rlist):
			rlist.append(rdata)
			dnsDict[rrname]=rlist
	  else:
		rlist = []
		rlist.append(rdata)
		dnsDict[rrname] = rlist
		
	  rlist = dnsDict[rrname]
	  if (rlist):
		dnsCount[rrname] = len(rlist)
	  else:
		dnsCount[rrname] = 0
		
  items = [(v,k) for k, v in dnsCount.items()]
  items.sort()
  items.reverse()
  items = [(k,v) for v,k in items]
  
  for item in items:
	print '[+] Host: ' +str(item[0]) +' ,Unique IP Addresses: '+str(item[1])
	##print 

  
	  #e = Website(item)
	  #e.linklabel = 'Unique IPs:\n' + str(x)
	  #e.linkcolor = 0x9933FF
	  #response += e
  #return response