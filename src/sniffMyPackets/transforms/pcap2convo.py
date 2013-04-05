#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, Host
from canari.maltego.message import Field, Label, MatchingRule
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
    description='Maps TCP/UDP Conversations',
    uuids=[ 'sniffMyPackets.v2.pcap2TCPConvo' ],
    inputs=[ ( 'sniffMyPackets', Host ) ],
    debug=True
)
def dotransform(request, response):
    
  convo = []
  
  srcip = request.value
  dstip = request.fields['sniffMyPackets.hostdst']
  pcap = request.fields['pcapsrc']
  srcport = request.fields['sniffMyPackets.hostsport']
  dstport = request.fields['sniffMyPackets.hostdport']
  
  pkts = rdpcap(pcap)
  
  for x in pkts:
	if x.haslayer(IP) and x.haslayer(TCP) and x.getlayer(TCP).sport == int(srcport) and x.getlayer(TCP).dport == int(dstport):
	  src = x.getlayer(IP).src
	  dst = x.getlayer(IP).dst
	  sport = x.getlayer(TCP).sport
	  dport = x.getlayer(TCP).dport
	  chatter = src, dst, sport, dport, 'tcp'
	  if chatter not in convo:
		convo.append(chatter)
  
  for y in pkts:
	if y.haslayer(IP) and y.haslayer(UDP) and y.getlayer(UDP).sport == int(srcport) and y.getlayer(UDP).dport == int(dstport):
	  src = y.getlayer(IP).src
	  dst = y.getlayer(IP).dst
	  sport = y.getlayer(UDP).sport
	  dport = y.getlayer(UDP).dport
	  chatter = src, dst, sport, dport, 'udp'
	  if chatter not in convo:
		convo.append(chatter)
  
  
  for src, dst, sport, dport, proto in convo:
	if int(srcport) == int(sport):
	  talker = dst, dport
	  e = Host(talker)
	  e.hostsrc = dst
	  e.hostdst = src
	  e.hostsport = dport
	  e.hostdport = sport
	  e.linklabel = proto
	  if proto == 'tcp':
		e.linkcolor = 0x2314CA
	  if proto == 'udp':
		e.linkcolor = 0x0E7323
	  e += Field('pcapsrc', pcap, displayname='Original pcap File')
	  response += e

  return response

