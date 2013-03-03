#!/usr/bin/env python

#from canari.maltego.utils import debug, progress
from common.entities import wifuClient, accessPoint
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
    label='WiFi Client 2 AP [U]',
    description='Runs a transform against a wireless client and creates an accesspoint entity',
    uuids=[ 'sniffMyPackets.v2.Client2AP' ],
    inputs=[ ( 'sniffMyPackets', wifuClient ) ],
    debug=False
)
def dotransform(request, response):
  
	if 'sniffMyPackets.clientSSID' in request.fields:
	    response += accessPoint(request.fields['sniffMyPackets.clientSSID'])
	  
	return response
    
