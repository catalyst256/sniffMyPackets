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
    label='L3 - Map DNS request to Client IP [SmP]',
    description='Maps a IPv4 Address from a DNS query',
    uuids=[ 'sniffMyPackets.v2.dnsrequest_2_client' ],
    inputs=[ ( 'sniffMyPackets', Domain ) ],
    debug=True
)
def dotransform(request, response):

    domain = request.value
    pcap = request.fields['pcapsrc']
    clientip = []

    pkts = rdpcap(pcap)

    for p in pkts:
        if p.haslayer(DNS) and p.haslayer(DNSRR):
            dname = p.getlayer(DNSRR).rrname
            cip = p.getlayer(IP).dst
            ddata = dname, cip
            clientip.append(ddata)

    for dname, cip in clientip:
        if dname == domain:
            e = IPv4Address(cip)
            e += Field('pcapsrc', pcap, displayname='Original pcap File')
            e.linklabel = 'Client'
            response += e
        return response
