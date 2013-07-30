#!/usr/bin/env python
import csv, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import Host, Service
from canari.maltego.message import Field, Label, UIMessage
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
    label='Identify Service [pcap]',
    description='Looks to match a service to a port',
    uuids=[ 'sniffMyPackets.v2.identify_2_service' ],
    inputs=[ ( 'sniffMyPackets', Host ) ],
    debug=False
)
def dotransform(request, response):
    
    services = csv.reader(open('sniffMyPackets/transforms/common/services.csv', 'r'))
    pcap = request.fields['pcapsrc']
    dport = request.fields['sniffMyPackets.hostdport']
    proto = request.fields['proto']

    s_name = ''

    for row in services:
        if dport == row[1] and proto == row[2]:
            s_name = row[0]
            if s_name == ' ':
                s_name = 'Unknown'


    e = Service(s_name)
    e.linklabel = proto + ':' + dport
    e.linkcolor = 0x0B615E
    e += Field('pcapsrc', pcap, displayname='Original pcap File')
    e += Field('id_dport', dport, displayname='Original Destination port')
    response += e

    return response