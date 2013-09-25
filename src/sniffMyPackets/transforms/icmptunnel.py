#!/usr/bin/env python

import logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, WarningAlert
from canari.maltego.message import Label
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
    label='L4 - Look for ICMP Tunnels [SmP]',
    description='Looks through pcap and tries to identify ICMP tunnels',
    uuids=[ 'sniffMyPackets.v2.pcap_2_icmptunnel' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):

    pcap = request.value
    pkts = rdpcap(pcap)

    icmp_req = []
    icmp_rep = []
    icmp_payload = ['0123567', 'abcdef']
    suspicious = 0


    for p in pkts:
        if p.haslayer(IP) and p.haslayer(ICMP):
            if p[ICMP].type == 8:
                icmp_req.append(p)
            if p[ICMP].type == 0:
                icmp_rep.append(p)

        if p.haslayer(Raw):
            load = str(p[Raw].load)
            for x in icmp_payload:
                if x in load:
                    suspicious = 1

    a = len(icmp_req)
    b = len(icmp_rep)

    print suspicious
    # print icmp_payload

    if a > b and suspicious == 1:
        e = WarningAlert('ICMP Tunnel')
        response += e

    return response