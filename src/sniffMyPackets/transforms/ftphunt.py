#!/usr/bin/env python

import os
from common.entities import pcapFile
from canari.maltego.entities import IPv4Address
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
    label='Find FTP Traffic [pcap]',
    description='Looks for FTP Traffic against an IP address',
    uuids=[ 'sniffMyPackets.v2.IPAddress2FTP' ],
    inputs=[ ( 'sniffMyPackets', IPv4Address ) ],
    debug=True
)
def dotransform(request, response):
    
    pcap = request.fields['pcapsrc']
    sport = request.fields['convosrc']
    srcip = request.value
    filename = '/tmp/ftp-' + str(srcip) + '.cap'
    
    sharkit = 'tshark -r ' + pcap + ' -R "ftp || ftp-data && ip.host=="' + str(srcip) + ' -w ' + filename + ' -F libpcap'
    os.system(sharkit)
    
    e = pcapFile(filename)
    response += e
    return response
