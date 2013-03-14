#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os, sys
from multiprocessing import Process
from common.entities import monitorInterface, accessPoint
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
    label='Hunt for Hidden Networks [U]',
    description='Looks for wireless networks that are hidden',
    uuids=[ 'sniffMyPackets.v2.HuntforHidden' ],
    inputs=[ ( 'sniffMyPackets', monitorInterface ) ],
    debug=True
)
def dotransform(request, response):
    
    hiddenNets = []
    unhiddenNets = []
    
    interface = request.value
    
    def sniffDot11(p):
      if p.haslayer(Dot11ProbeResp):
	addr2 = p.getlayer(Dot11).addr2
	if (addr2 in hiddenNets) & (addr2 not in unhiddenNets):
	  netName = p.getlayer(Dot11ProbeResp).info
	  print '[!] Declocked Hidden SSID: ' +netName + ' for MAC: '+addr2
	if p.haslayer(Dot11Beacon):
	  if p.getlayer(Dot11Beacon).info == '':
	    addr2 = p.getlayer(Dot11).addr2
	  if addr2 not in hiddenNets:
	    print '[-]Detectecd Hidden SSID: ' + 'with MAC: @' +addr2
	    hiddenNets.append(addr2)
    
    sniff(iface=interface, prn=sniffDot11, count=1000)
    #return response

