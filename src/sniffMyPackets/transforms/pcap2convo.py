#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
#from canari.maltego.utils import debug, progress
from common.entities import pcapFile
from canari.maltego.entities import IPv4Address
from canari.maltego.message import Field
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
    label='Find TCP Convo [pcap]',
    description='Looks for conversations between IP in pcap file',
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
    #pkts.summary()
    
    for x in pkts:
      if x.haslayer(IP) and x.getlayer(IP).src == srcip:
	destip = x.getlayer(IP).dst
	if x.haslayer(TCP):
	  sport = x.getlayer(TCP).sport
	  dport = x.getlayer(TCP).dport
	  chatter = srcip, sport, destip, dport
	  if chatter not in convo:
	    convo.append(chatter)
    
    for source, sourceport, destination, destinationport in convo:
      e = IPv4Address(destination)
      e += Field('convodst',destinationport, displayname='Destination Port', matchingrule='loose')
      e += Field('convosrc', sourceport, displayname='Source Port', matchingrule='loose')
      response += e
    return response



