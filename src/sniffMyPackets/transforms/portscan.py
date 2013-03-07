#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import Port
from canari.maltego.entities import IPv4Address
from canari.maltego.message import Field, MatchingRule
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
    label='Port Scan [A]',
    description='Runs a port scan against an IP address',
    uuids=[ 'sniffMyPackets.v2.Portscan2IPAddress' ],
    inputs=[ ( 'sniffMyPackets', IPv4Address ) ],
    debug=True
)
def dotransform(request, response):
	
	target = request.value
	e = Port
	ans,uans = sr(IP(dst=target)/TCP(dport=[23,22,80,443,8080,3389,25]), timeout=10, verbose=0)
	#ans.show()
	for send,rcv in ans:
	  if rcv.getlayer(TCP).flags == 0x012:
		x = Port((rcv.getlayer(TCP).sport), matching_rule=MatchingRule.Loose)
		#x.PortNumber(rcv.getlayer(TCP).sport)
		x.PortState = 'Open'
		response += x
	return response
