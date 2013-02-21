#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import SniffmypacketsEntity, monitorInterface, accessPoint
from canari.maltego.utils import debug, progress
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
    label='Sniffs for WiFi Beacon Frames',
    description='Listens for wifi beacon frames on specified mon0 interface',
    uuids=[ 'sniffMyPackets.v2.sniffBeaconFrames' ],
    inputs=[ ( 'sniffMyPackets', monitorInterface ) ],
    debug=True
)
def dotransform(request, response):
  
    beaconFrames = []
    interface = request.value
    
    def sniffBeacon(p):
	  if p.haslayer(Dot11Beacon):
		netName = p.getlayer(Dot11Beacon).info
		mac = p.getlayer(Dot11).addr2
		station = netName + ',' + mac
		if station not in beaconFrames:
		  beaconFrames.append(station)
    
    sniff(iface=interface, prn=sniffBeacon, count=100)
    for x in beaconFrames:
	  #beaconFrames = x.split(",")
	  e = accessPoint(x)
	  #e.maccaddress = x[1]
	  response += e
    return response

