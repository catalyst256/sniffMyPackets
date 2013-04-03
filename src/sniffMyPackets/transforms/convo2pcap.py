#!/usr/bin/env python


import os
#from canari.maltego.utils import debug, progress
from common.entities import pcapFile, Host
from canari.maltego.entities import IPv4Address
from canari.maltego.message import Field
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
    label='Write Convo [pcap]',
    description='Takes a TCP/UDP convo and saves out to pcap file',
    uuids=[ 'sniffMyPackets.v2.TCPConvo2pcapfile' ],
    inputs=[ ( 'sniffMyPackets', Host ) ],
    debug=False
)
def dotransform(request, response):
	
    pcap = request.fields['pcapsrc']
    dstip = request.fields['sniffMyPackets.hostdst']
    srcip = request.value
    sport = request.fields['sniffMyPackets.hostsport']
    dport = request.fields['sniffMyPackets.hostdport']
    filename = '/tmp/' + str(srcip) + '-' + str(sport) + '.cap'
    
    sharkit = 'tshark -r ' + pcap + ' -R "ip.dst==' + str(dstip) + ' and ip.src==' + str(srcip) + ' and tcp.dstport==' + str(dport) + ' and tcp.srcport==' + str(sport) + '"' + ' -w ' + filename + ' -F libpcap'
    os.system(sharkit)
    
    e = pcapFile(filename)
    response += e
    return response
    
	
