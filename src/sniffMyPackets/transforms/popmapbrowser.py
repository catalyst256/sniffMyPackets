#!/usr/bin/env python

import os
from common.entities import GeoMap
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
    label='L3 - Open Map in Browser [SmP]',
    description='Opens Map in default browser',
    uuids=[ 'sniffMyPackets.v2.openmap_in_browser' ],
    inputs=[ ( 'sniffMyPackets', GeoMap ) ],
    debug=True
)
def dotransform(request, response):
    
    gmap = request.value
    cmd = 'xdg-open ' + gmap
    os.system(cmd)
    return response
