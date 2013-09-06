#!/usr/bin/env python

import logging, sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from canari.easygui import multenterbox
from common.entities import pcapFile
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
    label='L0 - Rewrite pcap file for replay [SmP]',
    description='Rewrites source & destination IP address in a TCP stream',
    uuids=[ 'sniffMyPackets.v2.pcap2rewrite' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pcap = request.value
    pkts = rdpcap(pcap)

    msg = 'Enter the new IPs to rewrite the pcap file with'
    title = 'L0 - Rewrite pcap file for replay [SmP]'
    fieldNames = ''
    fieldValues = ''

    for p in pkts:
        del p[IP].chksum
        del p[TCP].chksum

    new_file = request.value[52:]

    print new_file

    return response
