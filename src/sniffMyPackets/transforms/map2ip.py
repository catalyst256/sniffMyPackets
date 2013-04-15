#!/usr/bin/env python

from common.entities import Host
from canari.maltego.message import UIMessage, Field
from canari.maltego.entities import IPv4Address, Domain
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
    label='Map to IPv4Address [pcap]',
    description='Maps entity to single IP address to show relationships',
    uuids=[ 'sniffMyPackets.v2.map2ip_domain', 'sniffMyPackets.v2.map2ip_host' ],
    inputs=[ ( 'sniffMyPackets', Domain ), ( 'sniffMyPackets', Host ) ],
    debug=True
)
def dotransform(request, response):

  try:
    srcip = request.fields['hostsrc']
  except:
    srcip = request.fields['sniffMyPackets.hostsrc']

  if srcip is not None:
    e = IPv4Address(srcip)
    response += e
    return response
  else:
    return response + UIMessage('Does not contain Source IP field')
      
