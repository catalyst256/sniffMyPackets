#!/usr/bin/env python

import os
from common.entities import pcapFile
from canari.maltego.message import UIMessage
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
    label='ngpcap to pcap [pcap]',
    description='Converts a non libpcap file to libpcap for use with Scapy',
    uuids=[ 'sniffMyPackets.v2.convert_ngpcap2pcap' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    fileName = request.value
    cmd = 'editcap ' + fileName + ' -F libpcap ' + fileName
    os.system(cmd)
    
    return response + UIMessage('File Converted')
