#!/usr/bin/env python

#from canari.maltego.utils import debug, progress
from canari.framework import configure #, superuser
from common.entities import wiFiChannel, accessPoint

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
    label='AP to Channel',
    description='Takes the sniffMyPackets Access Point and creates a channel entity',
    uuids=[ 'sniffMyPackets.v2.AccessPoint2Channel' ],
    inputs=[ ( 'sniffMyPackets', accessPoint ) ],
    debug=True
)
def dotransform(request, response):

	if 'sniffMyPackets.channel' in request.fields:
		response += wiFiChannel(request.fields['sniffMyPackets.channel'])		 
	
	return response
