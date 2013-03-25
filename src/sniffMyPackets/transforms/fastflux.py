#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.entities import Website
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
    label='Check for FastFlux [pcap]',
    description='Checks a pcap file and looks for fastflux domains',
    uuids=[ 'sniffMyPackets.v2.check4fastflux' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
	
  dnsRecords = {}
  def handlePkt(pkt):
    if pkt.haslayer(DNSRR):
        rrname = pkt.getlayer(DNSRR).rrname
        rdata = pkt.getlayer(DNSRR).rdata
        if dnsRecords.has_key(rrname):
            if rdata not in dnsRecords[rrname]:
                dnsRecords[rrname].append(rdata)
        else:
            dnsRecords[rrname] = []
            dnsRecords[rrname].append(rdata)
	
  pkts = rdpcap(request.value)
  for pkt in pkts:
    handlePkt(pkt)
  for item in dnsRecords:
    if int(len(dnsRecords[item])) >= 5:
	  e = Website(item)
	  e += Field('pcapsrc', request.value, displayname='Original pcap File', matchingrule='loose')
      e.linklabel = ftype 
