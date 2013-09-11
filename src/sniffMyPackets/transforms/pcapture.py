#!/usr/bin/env python

import logging, hashlib
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import time
from common.entities import Interface, pcapFile
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
    label='L0 - Capture Packets [SmP]',
    description='Sniffs packets on interface and saves to file',
    uuids=[ 'sniffMyPackets.v2.interface2pcap' ],
    inputs=[ ( 'sniffMyPackets', Interface ) ],
    debug=True
)
def dotransform(request, response):
  
    interface = request.value
    tmpfolder = request.fields['sniffMyPackets.tmpfolder']
    tstamp = int(time())
    fileName = tmpfolder + '/' +str(tstamp)+'.pcap' 
    
    if 'sniffMyPackets.count' in request.fields:
      pktcount = int(request.fields['sniffMyPackets.count'])
    else:
      pktcount = 300
    
    pkts = sniff(iface=interface, count=pktcount)
    
    wrpcap(fileName, pkts)
    
    sha1hash = ''
    fh = open(fileName, 'rb')
    sha1hash = hashlib.sha1(fh.read()).hexdigest()
        
    e = pcapFile(fileName)
    e.sha1hash = sha1hash
    response += e
    return response
