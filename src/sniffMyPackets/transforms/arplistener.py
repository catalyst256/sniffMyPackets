#!/usr/bin/env python

import logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.entities import IPv4Address
from canari.maltego.message import Label
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
    label='Read ARP packets [pcap]',
    description='Looks through a pcap file and returns IPs from ARP requests',
    uuids=[ 'sniffMyPackets.v2.readarppackets' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
  
  pkts = rdpcap(request.value)
  hosts = []
  
  for p in pkts:
	if p.haslayer(ARP):
	  src = p.getlayer(ARP).psrc
	  if src not in hosts:
		hosts.append(src)
  
  for x in hosts:
	e = IPv4Address(x)
	e.linklabel = 'ARP'
	response += e
  return response
