#!/usr/bin/env python


import logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, UserLogin
from canari.maltego.message import Field
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
    label='SMTP Auth Hunt',
    description='Reads a pcap file and looks for SMTP Auth username/password then decrypts it',
    uuids=[ 'sniffMyPackets.v2.smtpauthbase64' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
  
  pkts = rdpcap(request.value)
  creds = []
  smtpresp = 334
  
  for x in pkts:
    if x.haslayer(TCP) and x.haslayer(Raw):
      raw = x.getlayer(Raw).load
      print raw
  
  #return response
