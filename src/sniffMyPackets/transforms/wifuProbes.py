#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os, sys
from multiprocessing import Process
from common.entities import monitorInterface, accessPoint, wifuClient
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
    'dotransform',
    'onterminate'
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
	
    clientMAC = str(request.value)
    ap = []
    if 'sniffMyPackets.monInt' in request.fields:
      interface = request.fields['sniffMyPackets.monInt']
    
    def sniffBeacon(p):
	  if p.haslayer(Dot11ProbeReq) and p.getlayer(Dot11).addr2 == clientMAC:
	    netName = p.getlayer(Dot11ProbeReq).info
	    mac = p.getlayer(Dot11).addr2
	    station = netName, mac
	    if station not in ap:
	      ap.append(station)
		  
    def channel_hopper():
      channel = random.randrange(1,15)
      os.system("iw dev %s set channel %d" % (interface, channel))
      time.sleep(1)
  
    # Start the channel hopping
    x = Process(target = channel_hopper)
    x.start()
    
    sniff(iface=interface, prn=sniffBeacon, count=500)
    for ssid, mac in ap:
	  if ssid != '':
	    e = accessPoint(ssid)
	    e.apbssid = mac
	    response += e
    return response

def onterminate():
  # Kill the channel hopping process
  x.terminate()
  sys.exit(0)
