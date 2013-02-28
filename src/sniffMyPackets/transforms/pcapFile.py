#!/usr/bin/env python


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, accessPoint #, pcapStream
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
    label='Reads a pcap file',
    description='Reads a pcap file and maps out AP\'s and Clients [wiFu]',
    uuids=[ 'sniffmyPackets.v2.pcapFiletoWifiMap' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
	
	beacons = []
	clients = []
	pcap = rdpcap(request.value)
	
	for pkt in pcap:
	  if pkt.haslayer(Dot11Beacon):
		ssid = pkt.getlayer(Dot11Beacon).info
		if ssid not in beacons:
		  beacons.append(ssid)
		  response += accessPoint(ssid)	  	   
	  
	return response
