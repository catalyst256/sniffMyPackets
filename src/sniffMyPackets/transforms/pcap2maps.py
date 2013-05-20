#!/usr/bin/env python

from time import time as ttime
import pygeoip, sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile, GeoMap
from canari.maltego.message import UIMessage
from canari.framework import configure #, superuser

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Sniffmypackets Project'
__credits__ = 'This code is based on Michael Ligh original googlegeoip.py code, just tweaked for my needs' 

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
    label='Build Map [pcap]',
    description='Builds a Google Map based on IP address origin',
    uuids=[ 'sniffMyPackets.v2.pcapfile_2_googlemaps' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):

    geo_header = """<html><head>
    <script type="text/javascript" src="http://www.google.com/jsapi"></script>
    <script type="text/javascript">
        google.load('visualization', '1', {packages: ['geomap']});
    </script>
    <script type="text/javascript">
        function drawVisualization() {
        // Create and populate the data table.
        var data = new google.visualization.DataTable();
        data.addColumn('string', '', 'Country');
        data.addColumn('number', 'Hosts');
        """

    geo_footer = """
        var geomap = new google.visualization.GeoMap(document.getElementById('geo_map'));
        geomap.draw(data, null);
        }
    google.setOnLoadCallback(drawVisualization);
    </script>
    </head>
    <body>
    <div id="geo_map"></div>
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
    
    
    countries = {}
    
    for ip in ip_list:
        try:
            rec = gi.record_by_addr(ip)
        except:
            continue
        if rec == None:
            continue
        if 'country_code' not in rec.keys():
            continue
        if rec['country_code'] in countries.keys():
            countries[rec['country_code']] += 1
        else:
            countries[rec['country_code']] = 1
    
    map_code.append("    data.addRows(%d);" % (len(countries)) + '\n')
        
    c = 0
    for country, value in countries.items():
        map_code.append("    data.setValue(%d, 0, '%s');" % (c, country) + '\n')
        map_code.append("    data.setValue(%d, 1, %d);" % (c, value) + '\n')
        c += 1

    # Create the text output for a html file to save
    s = str(geo_header) + ' '.join(map_code) + str(geo_footer)

    # Create the file and save the output from s using time as a filename
    t = int(ttime())
    filename = '/tmp/' + str(t) + '.html'
    # print filename
    f = open(filename, 'w')
    f.write(s)
    f.close()

    # cmd = 'xdg-open ' + filename
    # os.system(cmd)

    # Return a GeoMap entity with the path to the html file
    e = GeoMap(filename)
    response += e
    return response
