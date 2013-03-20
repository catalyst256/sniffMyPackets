#!/usr/bin/env python

import os
#from canari.maltego.utils import debug, progress
from common.entities import pcapFile, FileDump
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
    label='HTTP ASCII Dump [pcap]',
    description='Reads a pcap and dumps HTTP as ASCII to file',
    uuids=[ 'sniffMyPackets.v2.HTTP_ASCII_dump2file' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):
    
    pcap = request.value
    filename = pcap + '.txt'
    cmd = 'tshark -r ' + pcap + ' -R "http" -z follow,tcp,ascii,0'
    a = os.popen(cmd).read()
    f = open(filename, 'w')
    f.write(a)
    f.close()
    e = FileDump('HTTP Dump')
    e.filelocation = filename
    e.rawdata = a
    response += e
    return response
