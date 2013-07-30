#!/usr/bin/env python
import os, hashlib, uuid
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
    label='Prepare pcap for use [pcap]',
    description='Runs some initial checks on pcapFile',
    uuids=[ 'sniffMyPackets.v2.preparepcap_for_use' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):

    pcap = request.value

    # Create a temporary folder for this particular pcap file and return as part of the pcapFile entity
    tmpfolder = '/tmp/'+str(uuid.uuid4())
    if not os.path.exists(tmpfolder):
        os.makedirs(tmpfolder) 

    # Run the pcapFile through a convertor to ensure it's the correct libpcap format
    cmd = 'editcap ' + pcap + ' -F libpcap ' + pcap
    os.system(cmd)

    # Hash the pcapFile and return both the SHA1 hash and the MD5 hash
    # sha1hash = ''
    fh = open(pcap, 'r')
    sha1hash = hashlib.sha1(fh.read()).hexdigest()

    fh = open(pcap, 'r')
    md5hash = hashlib.md5(fh.read()).hexdigest()
    # md5hash = ''

    e = pcapFile(pcap)
    e.sha1hash = sha1hash
    e.md5hash = md5hash
    e.outputfld = tmpfolder
    response += e
    return response