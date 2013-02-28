#!/usr/bin/env python

import logging
import os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import SniffmypacketsEntity, accessPoint, pcapFile
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
    label='Capture WPA Keys [U]',
    description='Performs captures for WPA Handshake',
    uuids=[ 'sniffMyPackets.v2.Deauth2Capture' ],
    inputs=[ ( 'sniffMyPackets', accessPoint ) ],
    debug=True
)
def dotransform(request, response):
    
	  WPAenc = []
	  ssid = request.value
	  buff = request.fields
	  interface = ''
	  channel = ''
	  for key, value in buff.iteritems():
		if key == 'sniffMyPackets.apmoninterface':
		  interface = value
		if key == 'sniffMyPackets.channel':
		  channel = value
	
	  
  
	  def captureWPA(pkts):
		for x in pkts:
		  if x.haslayer(Dot11AssoReq) or x.haslayer(EAPOL):
			if x not in WPAenc:
			  WPAenc.append(x)
	
	  os.system("iw dev %s set channel %s" % (interface, channel))
	  sniff(iface=interface, prn=captureWPA, count=50000)
		
	  fileName = ssid+'.cap'
	  wrpcap(fileName, WPAenc)
		
	  e = pcapFile(fileName)
	  response += e
	  
	  return response

