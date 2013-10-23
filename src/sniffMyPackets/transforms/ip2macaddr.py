#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import MacAddress
from canari.maltego.entities import IPv4Address
from canari.maltego.message import Field, UIMessage
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
    label='L4 - IP address to MAC address [SmP]',
    description='Returns MAC address from IPv4 Address',
    uuids=[ 'sniffMyPackets.v2.IPAddr_2_MACaddr' ],
    inputs=[ ( 'sniffMyPackets', IPv4Address ) ],
    debug=True
)
def dotransform(request, response):
    
    s_ip = request.value
    try:
        pcap = request.fields['pcapsrc']
    except:
        return response + UIMessage('Sorry this isnt a SmP IP Address')
    
    mac_list = []

    pkts = rdpcap(pcap)
    for x in pkts:
        if x.haslayer(IP) and s_ip == x[IP].src:
            mac = x[Ether].src
            if mac not in mac_list:
                mac_list.append(mac)

    for x in mac_list:
        e = MacAddress(x)
        e += Field('pcapsrc', pcap, displayname='Original pcap File')
        response += e
    return response
