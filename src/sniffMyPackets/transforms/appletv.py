#!/usr/bin/env python

import logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
#from canari.maltego.utils import debug, progress
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
    label='Hunt down AppleTV [pcap]',
    description='Looks through pcap file for AppleTV devices and checks for password protection',
    uuids=[ 'sniffMyPackets.v2.pcapfile2appletv' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pkts = rdpcap(request.value)
    passwd = 0 # no password set
    appledevice = []
    raw_mdns = []
    
    for pkt in pkts:
      if pkt.haslayer(UDP) and pkt.getlayer(UDP).sport == 5353:
	raw = pkt.getlayer(Raw).load
	srcip = pkt.getlayer(IP).src
	hwaddr = pkt.getlayer(Ether).src
	if raw not in raw_mdns:
	  raw_mdns.append(raw)
	  
    for x in raw_mdns:
      for s in re.search('pw=0', x):
	print s.group()
		
    #return response
