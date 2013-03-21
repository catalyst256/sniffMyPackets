#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
#from canari.maltego.utils import debug, progress
from common.dissector import *
from common.entities import pcapFile, File
from canari.framework import configure #, superuser

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Sniffmypackets Project'
__credits__ = 'The additional Scapy dissectors was written by cs_saheel@hotmail.com and can be found here: https://github.com/cssaheel/dissectors'

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
    label='Rebuild Files [pcap]',
    description='Rebuilds files from within pcap file',
    uuids=[ 'sniffMyPackets.v2.rebuildFilesFrompcap' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    dissector = Dissector()
    
    dissector.change_dfolder('/tmp/Files/')
    pcap = request.value
    
    pkts = dissector.dissect_pkts(pcap)
    
    
