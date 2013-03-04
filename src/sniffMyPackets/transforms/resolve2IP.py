#!/usr/bin/env python


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
#from canari.maltego.utils import debug, progress
from canari.framework import configure #, superuser
from common.entities import WirelessCard
from canari.maltego.entities import IPv4Address


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
    label='Resolve To IP [A]',
    description='Resolves your IP',
    uuids=[ 'sniffMyPackets.v2.Resolve2IP' ],
    inputs=[ ( 'sniffMyPackets', WirelessCard ) ],
    debug=True
)
def dotransform(request, response):
	interface = request.value
	conf.iface=interface
	ip = ''
	
	for x in conf.route.routes:
	  if x[3] == interface and x[2] == '0.0.0.0':
		ip = x[4]
		
	e = IPv4Address(ip)
	e.internal = True
	response += e
  
	return response