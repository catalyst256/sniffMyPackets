#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile,DHCPServer
from canari.maltego.message import Label, Field, UIMessage
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
    label='Find DHCP Servers [pcap]',
    description='Reads pcap file and returns DHCP servers and options',
    uuids=[ 'sniffMyPackets.v2.pcap2dhcpserver' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
  
  # Load the pcap file and store as pkts
  pkts = rdpcap(request.value)
  
  # Create empty list to store the output from the raw DHCP packetsl
  dhcp_raw = []
  
  # Parse through the packets looking only for BOOTP replies with op=0x02 (BOOTP Reply) and BOOTP ACK
  for x in pkts:
	if x.haslayer(BOOTP) and x.haslayer(DHCP) and x.getlayer(BOOTP).op == 0x02:
	  raw = x.getlayer(DHCP).options
	  if 0x05 in raw[0]:
		#print raw
		for line in raw:
		  dhcp_raw.append(line[1])
  
  if len(dhcp_raw) != 0:
    e = DHCPServer(dhcp_raw[1])
    e.dhcpsubnet = dhcp_raw[3]
    e.linklabel = dhcp_raw[2]
    e.dhcpns = dhcp_raw[5]
    e.dhcpgw = dhcp_raw[4]
    response += e
    return response
  else:
    return response + UIMessage('No DHCP Servers found!!')