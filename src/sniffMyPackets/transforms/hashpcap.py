#!/usr/bin/env python

import hashlib, os
from common.entities import pcapFile
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
    label='Hash pcap file [pcap]',
    description='Generates a SHA1 hash on a pcap file from a external source',
    uuids=[ 'sniffMyPackets.v2.pcap2sha1_hash' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):

	pcap = request.value
	
	filehash = ''
	fh = open(pcap, 'rb')
	filehash = hashlib.sha1(fh.read()).hexdigest() 

	e = pcapFile(pcap)
	e.sha1hash = filehash
	response += e
	return response