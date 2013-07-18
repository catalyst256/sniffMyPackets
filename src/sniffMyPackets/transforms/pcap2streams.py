#!/usr/bin/env python
import os, uuid, hashlib
from common.entities import pcapFile
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
    label='Rebuild pcap streams [pcap]',
    description='Takes a pcap file and pulls out the streams',
    uuids=[ 'sniffMyPackets.v2.pcapfile_2_streams' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pcap = request.value

    stream_index = []
    stream_file = []

    tmpfolder = '/tmp/'+str(uuid.uuid4())
    if not os.path.exists(tmpfolder): os.makedirs(tmpfolder)

    # Create a list of the streams in the pcap file and save them as an index
    cmd = 'tshark -r ' + pcap + ' -T fields -e tcp.stream'
    p = os.popen(cmd).readlines()
    for x in p:
        if x not in stream_index:
            stream_index.append(x)
    
    try:
        for y in stream_index:
            y = y.strip('\n')
            dumpfile = tmpfolder + '/stream' + y + '.dump'
            if 'stream.dump' in dumpfile:
                pass
            else:
                cmd = 'tshark -r ' + pcap + ' tcp.stream eq ' + y + ' -w ' + dumpfile
                if dumpfile not in stream_file:
                    stream_file.append(dumpfile)
                os.popen(cmd)
    except:
        pass

    # Now for the long bit...
    for s in stream_file:
        cut = tmpfolder + '/stream' + s[48:-5] + '.pcap'
        cmd = 'editcap ' + s + ' -F libpcap ' + cut
        os.popen(cmd)
        remove = 'rm ' + s
        os.popen(remove)

        # Count the number of packets
        cmd = 'tshark -r ' + cut + ' | wc -l'
        pktcount = os.popen(cmd).read()

        # Hash the file and return a SHA1 sum
        sha1sum = ''
        fh = open(cut, 'rb')
        sha1sum = hashlib.sha1(fh.read()).hexdigest()

        e = pcapFile(cut)
        e.sha1hash = sha1sum
        e += Field('pcapsrc', request.value, displayname='Original pcap File', matchingrule='loose')
        e += Field('pktcnt', pktcount, displayname='Number of packets', matchingrule='loose')
        e.linklabel = '# of pkts:' + str(pktcount)
        response += e

    return response
