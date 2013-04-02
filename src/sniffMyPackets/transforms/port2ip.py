#!/usr/bin/env python

from common.entities import port
from canari.maltego.entities import IPv4Address
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
    label='Port to IP [pcap]',
    description='Matches a port to an Destination IP',
    uuids=[ 'sniffMyPackets.v2.port2ip' ],
    inputs=[ ( 'sniffMyPackets', port ) ],
    debug=False
)
def dotransform(request, response):
  
  ipaddr = []
  
  ipaddr.append(request.fields['sniffMyPackets.dstip'])
  ipaddr.append(request.fields['sniffMyPackets.srcip'])
  sport = request.fields['sniffMyPackets.srcport']
  dport = request.fields['sniffMyPackets.dstport']
  
  #print ipaddr
  for x in ipaddr:
    e = IPv4Address(x)
    #e.linklabel = dport
    response += e
  return response
