#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os, sys
from multiprocessing import Process
from common.entities import SniffmypacketsEntity, monitorInterface, accessPoint
from canari.maltego.utils import debug, progress
from canari.framework import configure #, superuser

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Sniffmypackets Project'
__credits__ = 'This transform is based off the airoscapy code which can be found here: http://www.thesprawl.org/projects/airoscapy/'

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'catalyst256'
__email__ = 'catalyst256@gmail.com'
__status__ = 'Development'

__all__ = [
    'dotransform',
    'onterminate'
]


#@superuser
@configure(
    label='Sniff for WiFi Beacon Frames [U]',
    description='Listens for wifi beacon frames on specified mon0 interface',
    uuids=[ 'sniffMyPackets.v2.sniffBeaconFrames' ],
    inputs=[ ( 'sniffMyPackets', monitorInterface ) ],
    debug=True
)
def dotransform(request, response):
  
  aps = []
  interface = request.value

  def sniffAP(p):
    
    if p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp):
                 
        ssid       = p[Dot11Elt].info
        bssid      = p[Dot11].addr3    
        channel    = int(ord(p[Dot11Elt:3].info))
        capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        
        if re.search("privacy", capability): enc = 'Y'
        else: enc  = 'N'

        entity = ssid, bssid, str(channel), enc
        if entity not in aps:
		  aps.append(entity)
  
  def channel_hopper():
    channel = random.randrange(1,15)
    os.system("iw dev %s set channel %d" % (interface, channel))
    time.sleep(1)
  
  # Start the channel hopping
  x = Process(target = channel_hopper)
  x.start()
  
  # Start sniffing packets
  sniff(iface=interface, prn=sniffAP, count=500)
  
  # Iterate through stored APs and create a sniffMyPackets entity
  for ssid, bssid, channel, enc in aps:
	e = accessPoint(ssid)
	e.apbssid = bssid
	e.apchannel = channel
	e.apencryption = enc
	response += e
  return response
  
def onterminate():
  # Kill the channel hopping process
  x.terminate()
  sys.exit(0)
