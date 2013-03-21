#!/usr/bin/env python

import os
from common.entities import pcapFile
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
    label='Check HTTP Content [pcap]',
    description='Checks pcap for HTTP content types',
    uuids=[ 'sniffMyPackets.v2.pullHTTPcontent' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pcap = request.value
    cmd = 'tshark -R "http.response and http.content_type contains application" -z "proto,colinfo,http.content_length,http.content_length" -z "proto,colinfo,http.content_type,http.content_type" -r ' + pcap
    a = os.popen(cmd).read()
    print a
    
    #return response
