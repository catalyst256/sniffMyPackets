#!/usr/bin/env python


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.message import UIMessage
from canari.maltego.entities import Website
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
    label='Search for DNS Entries [pcap]',
    description='Reads a pcap file looks for DNS responses',
    uuids=[ 'sniffmyPackets.v2.pcapFiletoDNS' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
  
	dns_results = []
	
	pcap = request.value
	pkt = rdpcap(pcap)
	
	for pkts in pkt:
	  if pkts.haslayer(DNS) and pkts.getlayer(DNS).qr == 0:
		x = pkts.getlayer(DNS).qd.qname
		if x not in dns_results:
		  dns_results.append(x)
	for item in dns_results:
		e = Website(item)
		response += e
	return response  
