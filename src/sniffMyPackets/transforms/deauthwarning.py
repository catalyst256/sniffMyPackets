#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, WarningAlert
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
    'dotransform',
    'onterminate'
]


#@superuser
@configure(
    label='Find suspected DeAuth Attack [pcap]',
    description='Looks for large numbers of Deauth Packets',
    uuids=[ 'sniffMyPackets.v2.Findwifi_deatuhattack' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
  pkts = rdpcap(request.value)
  deauth_packets = []
  station = []
  
  for p in pkts:
	if p.haslayer(Dot11) and p.haslayer(Dot11Deauth):
	  station.append(p.getlayer(Dot11).addr2)
	  rcode = p.getlayer(Dot11Deauth).reason
	  if p.getlayer(Dot11).addr2 == station and p.getlayer(Dot11Deauth).reason == rcode:
		deauth_packets.append(station)
  
  #for x in deauth_packets:
  print station
  print deauth_packets.count(station)
  
	
	  
  