#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os, sys
from common.entities import SniffmypacketsEntity, monitorInterface, accessPoint, wifuClient
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
    label='Hunt down Probes [U]',
    description='Listens for client wifi probe requests to previously connected wireless networks',
    uuids=[ 'sniffMyPackets.v2.sniffProbeRequests' ],
    inputs=[ ( 'sniffMyPackets', wifuClient ) ],
    debug=True
)
def dotransform(request, response):
	
    clientMAC = request.value
    ap = []
    interface = ''
    buff = request.fields
    for key, value in buff.iteritems():
	  if key == 'sniffMyPackets.monInt':
		interface = value
    
    print clientMAC
    print interface
    def sniffBeacon(p):
	  if p.getlayer(Dot11).addr1 == clientMAC:
	    print p
		#netName = p.getlayer(Dot11ProbeReq).info
		#mac = p.getlayer(Dot11).addr1
		#station = netName, mac
		#if station not in ap:
		  #ap.append(station)
		  
    #channel = random.randrange(1,15)
    #os.system("iw dev %s set channel %d" % (interface, channel))
    #time.sleep(1)
    sniff(iface=interface, prn=sniffBeacon, count=1000)
    #for x in ap:
	  #e = accessPoint(x)
	  #response += e
    #return response
