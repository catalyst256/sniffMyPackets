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
    'Port'
]

class SniffmypacketsEntity(Entity):
    namespace = 'sniffMyPackets'
    
 
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

@EntityField(name='sniffMyPackets.dstport', propname='dstport', displayname='Dst Port', type=EntityFieldType.String, matchingrule='loose')
@EntityField(name='sniffMyPackets.srcport', propname='srcport', displayname='Src Port', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.dstip', propname='dstip', displayname='Dst IP', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.srcip', propname='srcip', displayname='Src IP', type=EntityFieldType.String)
class port(SniffmypacketsEntity):
  pass  