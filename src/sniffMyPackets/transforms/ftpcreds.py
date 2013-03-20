#!/usr/bin/env python

import logging
import re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.entities import Phrase
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
    label='Look for FTP Creds [pcap]',
    description='Search pcap file for FTP creds',
    uuids=[ 'sniffMyPackets.v2.pcapFile2ftpCreds' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pcap = request.value
    pkts = rdpcap(pcap)
    pkts.summary()
    last_user = ''
    last_passwd = ''
        
    for x in pkts:
      dport= x.sprintf("%IP.dport%")
      raw = x.sprintf("%Raw.load%")
      if dport == 21:

