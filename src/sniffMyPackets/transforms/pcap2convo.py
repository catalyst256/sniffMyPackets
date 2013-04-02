#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
#from canari.maltego.utils import debug, progress
from common.entities import pcapFile, port
#from canari.maltego.entities import IPv4Address
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
    description='Maps TCP/UDP ports to Source IPs',
    uuids=[ 'sniffMyPackets.v2.pcap2TCPConvo' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
  convo = []
  chitchat = []
  pcap = request.value
  pkts = rdpcap(pcap)
  
  for x in pkts:
    if x.haslayer(IP) and x.haslayer(TCP):
      destip = x.getlayer(IP).dst
      srcip = x.getlayer(IP).src
      sport = str(x.getlayer(TCP).sport)
      dport = x.getlayer(TCP).dport
      proto = 'tcp'
      talk = sport, dport
      if talk not in chitchat:
		chitchat.append(talk)
		for s in chitchat:
		  chatter = srcip, sport, destip, dport, proto
		  if chatter not in convo:
			convo.append(chatter)

  for y in pkts:
	if y.haslayer(UDP):
	  sport = y.getlayer(UDP).sport
	  dport = y.getlayer(UDP).dport
	  proto = 'udp'
	  chatter = srcip, sport, destip, dport, proto
	  if chatter not in convo:
		convo.append(chatter)

  for source, sourceport, destination, destinationport, proto in convo:
    portlabel = 'scrip: ' + str(source) + '\n' + 'srcport: ' + str(sourceport) + '\n' + 'dstip: ' + str(destination) + '\n' + 'dstport: ' + str(destinationport)
    e = port(portlabel)
    e.dstport = destinationport
    e.srcport = sourceport
    e.dstip = destination
    e.srcip = source
    if proto == 'tcp':
      e.linkcolor = 0x0000FF
      e.linklabel = 'tcp'
    if proto == 'udp':
	  e.linkcolor = 0xFE2E2E
	  e.linklabel = 'udp'
    e += Field('pcapsrc', pcap, displayname='Original pcap File', matchingrule='strict')
    response += e
  return response



