#!/usr/bin/env python

import logging
import os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import accessPoint, pcapFile
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
    label='Capture WPA Keys [U]',
    description='Performs captures for WPA Handshake',
    uuids=[ 'sniffMyPackets.v2.Deauth2Capture' ],
    inputs=[ ( 'sniffMyPackets', accessPoint ) ],
    debug=True
)
def dotransform(request, response):
    
	  eapol_packets = []
	  ssid = request.value
	  if 'sniffMyPackets.apmoninterface' in request.fields:
	    interface = request.fields['sniffMyPackets.apmoninterface']
	  if 'sniffMyPackets.channel' in request.fields:
	    channel = request.fields['sniffMyPackets.channel']
  
	  def sniffEAPOL(p):
		if p.haslayer(Dot11Auth):
		  eapol_packets.append(p)
		if p.haslayer(EAPOL):
		  eapol_packets.append(p)
	  
	  os.system("iw dev %s set channel %s" % (interface, channel))
	  
	  for i in range(1, 10):
		sniff(iface=interface, prn=sniffEAPOL, count=1000)
	  
	  fileName = ssid+'.cap'
	  wrpcap(fileName, eapol_packets)
		
	  e = pcapFile(fileName)
	  response += e
	  
	  return response

