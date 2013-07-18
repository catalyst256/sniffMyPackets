#!/usr/bin/env python
import os
from common.entities import pcapFile, pcapInfo
from canari.maltego.message import Field, Label
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
    label='Display pcap info [pcap]',
    description='Generate info about the pcap file',
    uuids=[ 'sniffMyPackets.v2.readpcap_2_info' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pcap = request.value

    pcap_info = []

    cmd = 'capinfos ' + pcap
    p = os.popen(cmd).readlines()
    print len(p)

    filename = pcap
    pktcount = p[4].strip('\n').split(' ')[5]
    duration = p[7].strip('\n').split(' ')[5:]
    start = p[8].strip('\n').split(' ')[11:]
    end = p[9].strip('\n').split(' ')[13:]
    sha1 = p[14].strip('\n').split(' ')[16]
    md5 = p[16].strip('\n').split(' ')[17]

    e = pcapInfo(filename)
    e.pktcount = pktcount
    e.duration = duration
    e.starttime = start
    e.endtime = end
    e.pcapsha1 = sha1
    e.pcapmd5 = md5
    response += e
    return response
