#!/usr/bin/env python

import logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
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
    label='Find SMTP Emails [pcap]',
    description='Read pcap file and look for SMTP emails within',
    uuids=[ 'sniffMyPackets.v2.pcap2smtp' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pcap = request.value
    pkts = rdpcap(pcap)
    records = []
    smtp_ports = [25, 587]

    for p in pkts:
        for x in smtp_ports:
            if p.haslayer(TCP) and p.getlayer(TCP).sport == x:
                dst = p.getlayer(IP).dst
                src = p.getlayer(IP).src
                dport = p.getlayer(TCP).dport
                sport = p.getlayer(TCP).sport
                record = src, dst, sport, dport, ack
                if record not in records:
                    records.append(record)
               
    for a, b, c, d, e in records:
        for p in pkts:
            if (a == p.getlayer(IP).src or p.getlayer(IP).dst) and (c == p.getlayer(TCP).sport or p.getlayer(TCP).dport) and (int(e) == p.getlayer(TCP).seq or p.getlayer(TCP).ack):
                load = p.getlayer(Raw).load
                # if load not in email_body:
                #     email_body.append


    print records
    print ack
    # return response
