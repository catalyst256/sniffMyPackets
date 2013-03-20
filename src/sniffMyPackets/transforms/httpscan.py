#!/usr/bin/env python

import logging
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
    label='HTTP Scan [pcap]',
    description='Scans a pcap file for HTTP requests',
    uuids=[ 'sniffMyPackets.v2.HTTPscan' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
	
	pcap = request.value
	get_requests = []
	pkts = rdpcap(pcap)
	
	for x in pkts:
	  if x.haslayer(IP) and x.getlayer(TCP).dport == 80:
		src = x.sprintf('%IP.src%')
		dst = x.sprintf('%IP.dst%')
		dstport = x.sprintf('%TCP.dport%')
		load = x.sprintf('%Raw.load%')
		if 'GET' not in load:
		  pass
		else:
		  traffic = src, dst, dstport, load
		  if x.getlayer(TCP).sport not in get_requests:
			get_requests.append(traffic)
	
	for srcip, dstip, dstport, raw in get_requests:
	  print '[+] ' + srcip + ' ----> ' + dstip + ':' + dstport
    #return response
