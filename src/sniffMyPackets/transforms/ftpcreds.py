#!/usr/bin/env python

import re, os
from common.entities import pcapFile, UserLogin
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
    label='Look for FTP Creds [pcap]',
    description='Search pcap file for FTP creds',
    uuids=[ 'sniffMyPackets.v2.pcapFile2ftpCreds' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):
  
  pcap = request.value
  user = []
  pw = ''
  
  cmd = 'tshark -r ' + pcap + ' -R "ftp && tcp.dstport == 21" -z follow,tcp,ascii,0'
  a = os.popen(cmd).read()
  user = re.findall("(?i)USER (.*)",a)
  pw = re.findall("(?i)PASS (.*)",a)
  creds = 'UserName:' + user[0] + '\r\nPassword:' + pw[0]

  e = UserLogin(creds)
  response += e
  return response