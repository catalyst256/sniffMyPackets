#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import time
from common.entities import monitorInterface, pcapFile, WirelessCard
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
    label='Sniff packets and saves to pcap file [U/A]',
    description='Sniffs packets on interface and saves to file',
    uuids=[ 'sniffMyPackets.v2.monitor2pcap', 'sniffMyPackets.v2.wirelesscard2pcap' ],
    inputs=[ ( 'sniffMyPackets', monitorInterface ), ( 'sniffMyPackets', WirelessCard ) ],
    debug=True
)
def dotransform(request, response):
  
    interface = request.value
    
    if 'sniffMyPackets.count' in request.fields:
      pktcount = request.fields['sniffMyPackets.count']
    else:
      pktcount = 300
    
    pkts = sniff(iface=interface, count=pktcount)
    tstamp = int(time())
    fileName = '/tmp/'+str(tstamp)+'.cap'
    wrpcap(fileName, pkts)
    e = pcapFile(fileName)
    response += e
    return response