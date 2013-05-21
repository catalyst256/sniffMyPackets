#!/usr/bin/env python

from time import time as ttime
import pygeoip, sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, GeoMap
from canari.maltego.message import UIMessage, Label
from canari.framework import configure #, superuser

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Sniffmypackets Project'
__credits__ = 'This code was initially based on Michael Ligh original googlegeoip.py code, however it is now the love child of that original code and Kippo Graph geomap code' 

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
    label='Build Geo IP Map [pcap]',
    description='Builds a Google Map based on IP address origin',
    uuids=[ 'sniffMyPackets.v2.pcapfile_2_googlemaps' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):

    geo_header = """<html><head>
    <script type="text/javascript" src="http://maps.google.com/maps?file=api&amp;v=2&amp;key=AIzaSyDEMaaLU6t3XuijBcO484BBhUoluqpnFa4"></script>
    <script type="text/javascript" src="http://www.google.com/jsapi"></script>
    <script type="text/javascript">
        google.load('visualization', '1', {packages: ['geomap']});
    </script>
    <script type="text/javascript">
        google.load("visualization", "1", {packages:["map"]});
        google.setOnLoadCallback(drawMap);
        function drawMap() {
        var data = new google.visualization.DataTable();
        data.addColumn('number','Lat');
        data.addColumn('number','Lon');
        data.addColumn('string','IP');
        """

    geo_footer = """
        var chart = new google.visualization.Map(document.getElementById('map_60aa'));
        chart.draw(data, {showTip:true});
        }
    google.setOnLoadCallback(drawVisualization);
    </script>
    </head>
    <body>
    <div id="map_60aa"></div>
    </body>
    </html>"""

    map_code = []

    # Download GeoIP Database from MaxMinds
    if not os.path.exists('/opt/geoipdb/geoipdb.dat'): 
        return response + UIMessage('Need local install of MaxMinds Geo IP database, use the download script in resource/external/geoipdownload.sh')
        
    gi = pygeoip.GeoIP('/opt/geoipdb/geoipdb.dat')

    pkts = rdpcap(request.value)

    ip_list = []

    # Create the IP list from the pcap file
    for x in pkts:
        if x.haslayer(IP):
            src = x.getlayer(IP).src
            if src != '0.0.0.0':
                ip_list.append(src)
    
    
    coordinates = []
    ip_exclusions = ['192.168.', '172.16.', '10.']

    for ip in ip_list:
        if ip_exclusions[0] in ip or ip_exclusions[1] in ip or ip_exclusions[2] in ip:
            pass
        else:
            rec = gi.record_by_addr(ip)
            lng = rec['longitude']
            lat = rec['latitude']
            coords = lat, lng, ip
            if coords not in coordinates:
                coordinates.append(coords)
    map_code.append("    data.addRows(%d);" % (len(coordinates)) + '\n')
        
    c = 0
    for lat, lng, src in coordinates:
        map_code.append("    data.setValue(%d, 0, %d);" % (c, lat) + '\n')
        map_code.append("    data.setValue(%d, 1, %d);" % (c, lng) + '\n')
        map_code.append("    data.setValue(%d, 2, '%s');" % (c, src) + '\n')
        c += 1

    # # Create the text output for a html file to save
    s = str(geo_header) + ' '.join(map_code) + str(geo_footer)

    # # Create the file and save the output from s using time as a filename
    t = int(ttime())
    filename = '/tmp/' + str(t) + '.html'
    f = open(filename, 'w')
    f.write(s)
    f.close()

    # # cmd = 'xdg-open ' + filename
    # # os.system(cmd)

    # Return a GeoMap entity with the path to the html file
    e = GeoMap(filename)
    e.linkcolor = 0x2314CA
    response += e
    return response
