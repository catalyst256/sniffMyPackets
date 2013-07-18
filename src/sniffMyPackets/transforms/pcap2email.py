#!/usr/bin/env python

import logging, re, uuid, glob
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
from common.dissectors.dissector import *
from common.entities import pcapFile, SMTPEmail
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
    label='Find SMTP Emails [pcap]',
    description='Read pcap file and look for SMTP emails within',
    uuids=[ 'sniffMyPackets.v2.pcap2smtp' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pcap = request.value
    pkts = rdpcap(pcap)
    
    tmpfolder = '/tmp/'+str(uuid.uuid4())
    if not os.path.exists(tmpfolder): os.makedirs(tmpfolder)

    streams = []

    smtp_ports = ['25', '587']

    for p in pkts:
        for s in smtp_ports:
            if p.haslayer(TCP) and p.getlayer(TCP).sport or p.getlayer(TCP).dport == s:
                streams.append(p)

    print len(streams)

    fh = open('/tmp/dump.pcap', 'w')
    for x in streams:
        fh.write(str(x))
    fh.close()

    dissector = Dissector() # instance of dissector class
    dissector.change_dfolder(tmpfolder)
    pkts = dissector.dissect_pkts('/tmp/dump.pcap')
    list_files = glob.glob(tmpfolder+'/*')

    print list_files


                # load = p.getlayer(Raw).load
                # ack = p.getlayer(TCP).ack
                # print load


      


    # return response
