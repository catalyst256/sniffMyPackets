#!/usr/bin/env python


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from canari.maltego.utils import debug, progress
from canari.framework import configure #, superuser
from canari.maltego.entities import IPv4Address, Website

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
    label='Sniff DNS Requests',
    description='Sniffs DNS requests and maps them to a client',
    uuids=[ 'sniffMyPackets.v2.DNS2Client' ],
    inputs=[ ( 'sniffMyPackets', IPv4Address ) ],
    debug=True
)
def dotransform(request, response):
    
    srcip = request.value
    
    
    return response

