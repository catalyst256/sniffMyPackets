#!/usr/bin/env python


import logging, base64, re
from common.entities import pcapFile, RebuiltFile
from canari.maltego.entities import EmailAddress
from canari.maltego.message import Field, Label
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
    label='SMTP Email Address Hunt [pcap]',
    description='Reads a file and looks for email addresses',
    uuids=[ 'sniffMyPackets.v2.smtpemailaddress' ],
    inputs=[ ( 'sniffMyPackets', RebuiltFile ) ],
    debug=True
)
def dotransform(request, response):
  
  headerdata = []
  msgfile = request.value
  lookFor = 'DATA'
  tmpfolder = request.fields['tmpfolder']
  
  
  # split the original file into two parts, message and header and save as lists
  with open(msgfile, mode='r') as msgfile:
    reader = msgfile.read()
    for i, part in enumerate(reader.split(lookFor)):
      if i == 0:
	headerdata.append(part)
  
  for x in headerdata:
    if s in re.finditer('(MAIL FROM: )(\S*) ', x):
      print s.group(1)
