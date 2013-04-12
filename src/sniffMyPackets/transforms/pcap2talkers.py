#!/usr/bin/env python

import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
#from canari.maltego.utils import debug, progress
from common.entities import pcapFile, Host
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
    label='Find TCP/UDP Talkers [pcap]',
    description='Search a pcap file and return all talkers based on SYN',
    uuids=[ 'sniffMyPackets.v2.pcap2talkers' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
  
  talkers = []
  pkts = rdpcap(request.value)
  
  for x in pkts:
	if x.haslayer(TCP) and x.getlayer(TCP).flags == 0x002:
	  src = x.getlayer(IP).src
	  dst = x.getlayer(IP).dst
	  sport = x.getlayer(TCP).sport
	  dport = x.getlayer(TCP).dport
	  talker = src, dst, sport, dport, 'tcp'
	  if talker not in talkers:
	    talkers.append(talker)
  
  for y in pkts:
	if y.haslayer(IP) and y.haslayer(UDP):
	  src = y.getlayer(IP).src
	  dst = y.getlayer(IP).dst
	  sport = y.getlayer(UDP).sport
	  dport = y.getlayer(UDP).dport
	  chatter = src, dst, sport, dport, 'udp'
	  if chatter not in talkers:
		talkers.append(chatter)
  
  
  for src, dst, sport, dport, proto in talkers:
	talker = src, sport
	e = Host(talker)
	e.hostsrc = src
	e.hostdst = dst
	e.hostsport = sport
	e.hostdport = dport
	e.linklabel = proto
	if proto == 'tcp':
	  e.linkcolor = 0x2314CA
	if proto == 'udp':
	  e.linkcolor = 0x0E7323
	e += Field('pcapsrc', request.value, displayname='Original pcap File', matchingrule='loose')
	response += e
  
  return response

