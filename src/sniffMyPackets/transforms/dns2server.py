#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from canari.maltego.entities import Domain, IPv4Address
from canari.maltego.message import UIMessage, Field, Label
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
    label='L3 - Map DNS request to Server IP [SmP]',
    description='Maps a DNS response made by client back to the server IP',
    uuids=[ 'sniffMyPackets.v2.dnsrequest_2_server' ],
    inputs=[ ( 'sniffMyPackets', Domain ) ],
    debug=True
)
def dotransform(request, response):
    
    domain = request.value
    pcap = request.fields['pcapsrc']
    domains = []

    pkts = rdpcap(pcap)

    for p in pkts:
        if p.haslayer(DNS) and p.haslayer(DNSRR):
            src_name = p.getlayer(DNSQR).qname
            src_ip = p.getlayer(DNSRR).rdata
            dtype = p.getlayer(DNSRR).type
            dnsrec = src_name, src_ip, dtype
            domains.append(dnsrec)

    for dname, dip, dtype in domains:
        if dname == domain and dtype == 1:
            e = IPv4Address(dip)
            e += Field('pcapsrc', pcap, displayname='Original pcap File')
            e.linklabel = 'Server'
            response += e

    return response
