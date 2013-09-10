#!/usr/bin/env python
import os, subprocess
from common.entities import GenericFile
# from canari.maltego.message import Field
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
    label='L4 - Open file in application [SmP]',
    description='Tries to open the file in its default application',
    uuids=[ 'sniffMyPackets.v2.Opensfile_in_application' ],
    inputs=[ ( 'sniffMyPackets', GenericFile ) ],
    debug=True
)
def dotransform(request, response):

    filepath = request.value
    subprocess.call(('gnome-open', filepath))
    return response