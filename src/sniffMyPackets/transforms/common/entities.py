#!/usr/bin/env python

from canari.maltego.message import Entity, EntityField, EntityFieldType, MatchingRule

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Sniffmypackets Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'catalyst256'
__email__ = 'catalyst256@gmail.com'
__status__ = 'Development'

__all__ = [
    'SniffmypacketsEntity',
    'pcapFile',
    'Interface',
    'FileDump',
    'RebuiltFile',
    'UserLogin',
    'Host',
    'AppleTV'
]

class SniffmypacketsEntity(Entity):
    namespace = 'sniffMyPackets'
    
@EntityField(name='sniffMyPackets.sha1hash', propname='sha1hash', displayname='SHA1 Hash', type=EntityFieldType.String)
class pcapFile(SniffmypacketsEntity):
    pass
    
class Interface(SniffmypacketsEntity):
    pass

@EntityField(name='sniffMyPackets.cip', propname='cip', displayname='Remote IP', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.cport', propname='cport', displayname='Local Port', type=EntityFieldType.String)
class FileDump(SniffmypacketsEntity):
    pass

@EntityField(name='sniffMyPackets.ftype', propname='ftype', displayname='File Type', type=EntityFieldType.String)
class RebuiltFile(SniffmypacketsEntity):
    pass
  
class UserLogin(SniffmypacketsEntity):
    pass

@EntityField(name='sniffMyPackets.hostsrc', propname='hostsrc', displayname='Source IP', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.hostdst', propname='hostdst', displayname='Destination IP', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.hostsport', propname='hostsport', displayname='Source Port', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.hostdport', propname='hostdport', displayname='Destination Port', type=EntityFieldType.String)
class Host(SniffmypacketsEntity):
  pass

class AppleTV(SniffmypacketsEntity):
    pass

@EntityField(name='sniffMyPackets.emailhash', propname='emailhash', displayname='SHA1 Hash', type=EntityFieldType.String)
class EmailMessage(SniffmypacketsEntity):
    pass