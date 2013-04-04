#!/usr/bin/env python


import logging, base64
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, UserLogin
from canari.maltego.message import Field, Label
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
    label='SMTP Auth Hunt [pcap]',
    description='Reads a pcap file and looks for SMTP Auth username/password then decrypts it',
    uuids=[ 'sniffMyPackets.v2.smtpauthbase64' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
  
  pkts = rdpcap(request.value)
  enccreds = []
  plaincreds = []
  acknum = []
  smtpresp = '334 '
  srcip = ''
  
  for x in pkts:
    if x.haslayer(TCP) and x.haslayer(Raw):
      raw = x.getlayer(Raw).load
      if str(smtpresp) in raw:
		srcip = x.getlayer(IP).src
		ack = x.getlayer(TCP).ack
		seq = x.getlayer(TCP).seq
		if ack not in acknum:
		  acknum.append(ack)
		
  for s in pkts:
	if s.haslayer(TCP) and x.haslayer(Raw):
	  seq = s.getlayer(TCP).seq
	  for a in acknum:
		if seq == a:
		  if s.getlayer(Raw).load not in enccreds: 
			enccreds.append(s.getlayer(Raw).load)
		  
  for c in enccreds:
	plaincreds.append(base64.b64decode(c))
  for e in plaincreds:
	e = UserLogin(e)
	e.linklabel = 'SMTP'
	e.linkcolor = 0xFF0000
	e += Field('srcip', srcip, displayname='Email Server IP')
	response += e
  return response
