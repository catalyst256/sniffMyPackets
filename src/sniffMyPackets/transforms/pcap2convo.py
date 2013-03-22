#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
#from canari.maltego.utils import debug, progress
from common.entities import pcapFile
from canari.maltego.entities import IPv4Address
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
    label='Find TCP/UDP Convo [pcap]',
    description='Looks for conversations between IPs in pcap file',
    uuids=[ 'sniffMyPackets.v2.pcap2TCPConvo' ],
    inputs=[ ( 'sniffMyPackets', IPv4Address ) ],
    debug=True
)
def dotransform(request, response):
    
  convo = []
  pcap = ''
  srcip = request.value
  if 'pcapsrc' in request.fields:
	pcap = request.fields['pcapsrc']
  pkts = rdpcap(pcap)
  destinationport = ''
  
  for x in pkts:
	if x.haslayer(IP) and x.getlayer(IP).src == srcip:
	  destip = x.getlayer(IP).dst
	  if x.haslayer(TCP):
		sport = x.getlayer(TCP).sport
		dport = x.getlayer(TCP).dport
		proto = 'tcp'
		chatter = srcip, sport, destip, dport, proto
		if chatter not in convo:
		  convo.append(chatter)
	  if x.haslayer(UDP):
		sport = x.getlayer(UDP).sport
		dport = x.getlayer(UDP).dport
		proto = 'udp'
		chatter = srcip, sport, destip, dport, proto
		if chatter not in convo:
		  convo.append(chatter)
  
  for source, sourceport, destination, destinationport, proto in convo:
	e = IPv4Address(destination)
	e += Label('Dst Port', destinationport)
	e.linklabel = destinationport, proto
	if proto == 'tcp':
	  e.linkcolor = 0x0000FF
	e += Field('convodst',destinationport, displayname='Destination Port', matchingrule='strict')
	e += Field('convosrc', sourceport, displayname='Source Port', matchingrule='strict')
	e += Field('pcapsrc', pcap, displayname='Original pcap File', matchingrule='loose')
	response += e
  return response



