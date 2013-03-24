#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.entities import Website
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
    label='Check HTTP Hosts [pcap]',
    description='Read a pcap file and return list of Hosts from GET requests',
    uuids=[ 'sniffMyPackets.v2.httpgetrequests2domain' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pkts = rdpcap(request.value)
    get_requests = []
    
    for x in pkts:
	  if x.haslayer(TCP) and x.haslayer(Raw):
		raw = x.getlayer(Raw).load
		for s in re.finditer('Host:(\S*\D\S*)', raw):
		  if s is not None:
		    rhost = s.group(1)
		    if rhost not in get_requests:
		      get_requests.append(rhost)
      
    for i in get_requests:
      e = Website(i)
      response += e
      return response
