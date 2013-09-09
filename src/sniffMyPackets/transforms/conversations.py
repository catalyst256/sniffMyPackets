#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, GenericFile
from canari.maltego.message import Field, Label, UIMessage
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
    label='L0 - Output Conversations to JPG [SmP]',
    description='TODO: Returns a Something entity with the phrase "Hello Word!"',
    uuids=[ 'sniffMyPackets.v2.conversations' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):

    pcap = request.value
    pkts = rdpcap(pcap)

    try:
        tmpfolder = request.fields['sniffMyPackets.outputfld']
    except:
        return response + UIMessage('No output folder defined, run the L0 - Prepare pcap transform')

    new_file = tmpfolder + '/conversations.svg'

    pkts.conversations(type='svg', target=new_file)

    e = GenericFile(new_file)
    response += e
    return response
