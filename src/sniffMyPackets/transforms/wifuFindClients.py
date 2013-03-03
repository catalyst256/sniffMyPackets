#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os, sys
from multiprocessing import Process
from common.entities import accessPoint, wifuClient
#from canari.maltego.utils import debug, progress
from canari.framework import configure #, superuser

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, SniffMyPackets Project'
__credits__ = 'The channel hopping technique was taken from the airoscapy project which can be found here: http://www.thesprawl.org/projects/airoscapy/'

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
    label='Find connected clients [U]',
    description='Listens for wifi probe responses to specified AP',
    uuids=[ 'sniffMyPackets.v2.sniffProbeResponses' ],
    inputs=[ ( 'sniffMyPackets', accessPoint ) ],
    debug=True
)
def dotransform(request, response):
  
    clients = []
    APssid = request.value
    if 'sniffMyPackets.apmoninterface' in request.fields:
      interface = request.fields['sniffMyPackets.apmoninterface']
    if 'sniffMyPackets.channel' in request.fields:
      channel = request.fields['sniffMyPackets.channel']
    if 'sniffMyPackets.bssid' in request.fields:
      bssid = request.fields['sniffMyPackets.bssid']
    
    def sniffProbe(p):
	  if p.haslayer(Dot11ProbeReq) and p.getlayer(Dot11ProbeReq).info == APssid:
		ssid = p.getlayer(Dot11ProbeReq).info
		cmac = p.getlayer(Dot11).addr1
		bssid = p.getlayer(Dot11).addr2
		#channel = int(ord(p[Dot11Elt:3].info))
		entity = ssid, cmac, bssid, channel
		if entity not in clients:
		  clients.append(entity)
    
    os.system("iw dev %s set channel %s" % (interface, channel))
    
    sniff(iface=interface, prn=sniffProbe, count=500)
    
    for ssid, cmac, bssid, channel in clients:
      e = wifuClient(cmac)
      e.clientBSSID = bssid
      e.monInt = interface
      e.clientSSID = ssid
      e.clientChannel = channel
      response += e
    return response
