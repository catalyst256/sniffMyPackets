#!/usr/bin/env python

import pygeoip, sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.entities import Location
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
    label='IP Address to GeoLoc [pcap]',
    description='Searchs pcap file and performs GeoIP Lookup',
    uuids=[ 'sniffMyPackets.v2.ip_2_geolocation' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):

    gi = pygeoip.GeoIP('/opt/geoipdb/geoipdb.dat')
    pkts = rdpcap(request.value)

    ip_raw = []
    ip_exclusions = ['192.168.', '172.16.', '10.']

    for x in pkts:
        if x.haslayer(IP):
            src = x.getlayer(IP).src
            if src != '0.0.0.0':
                if src not in ip_raw:
                    ip_raw.append(src)

    for s in ip_raw:
        if (ip_exclusions[1]) or ip_exclusions[0] or (ip_exclusions[2]) in s:
            print 'Error local Address Found ' + str(s)
        else:
            print s
            rec = gi.record_by_addr(s)
            city = rec['city']
            postcode = rec['postal_code']
            country = rec['country_name']
            lng = rec['longitude']
            lat = rec['latitude']
            google_map_url = 'https://maps.google.co.uk/maps?z=20&q=%s,%s' %(lat, lng)

    # return response
