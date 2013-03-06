#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import WirelessCard, Gateway
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
    label='Find Default Gateway [A]',
    description='Determines default gateway for ARP scan & MITM',
    uuids=[ 'sniffMyPackets.v2.WirelessCard2Gateway' ],
    inputs=[ ( 'sniffMyPackets', WirelessCard ) ],
    debug=True
)
def dotransform(request, response):
	
	interface = request.value
	conf.iface=interface
	gateway = ''
	for x in conf.route.routes:
	  if x[3] == interface and x[2] != '0.0.0.0':
		gateway = x[2]

	ans,uans = arping(str(gateway), verbose=0)
	
	for send,rcv in ans:
	  e = Gateway(gateway)
	  e.GatewayMAC = rcv.sprintf("%Ether.src%")
	  e.GatewayInt = interface
	  response += e
	return response


