#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os, sys
from multiprocessing import Process
from common.entities import accessPoint, wifuClient
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
    ssid = request.value
    apbssid = ''
    if 'sniffMyPackets.apmoninterface' in request.fields:
      interface = request.fields['sniffMyPackets.apmoninterface']
    if 'sniffMyPackets.channel' in request.fields:
      channel = request.fields['sniffMyPackets.channel']
    if 'sniffMyPackets.bssid' in request.fields:
      apbssid = request.fields['sniffMyPackets.bssid']
    
    def sniffProbe(p):
	  if p.haslayer(Dot11ProbeResp) and p.getlayer(Dot11).addr2 == apbssid:
		#if p.getlayer(Dot11).addr2 == apbssid:
		  ssid = p.getlayer(Dot11ProbeResp).info
		  cmac = p.getlayer(Dot11).addr1
		  #bssid = p.getlayer(Dot11).addr2
		  entity = ssid, cmac, channel
		  if entity not in clients:
			clients.append(entity)
    
    os.system("iw dev %s set channel %s" % (interface, channel))
    
    sniff(iface=interface, prn=sniffProbe, count=300)
    
    for ssid, cmac, channel in clients:
      e = wifuClient(cmac)
      e.clientBSSID = apbssid
      e.monInt = interface
      e.clientSSID = ssid
      e.clientChannel = channel
      response += e
    return response
