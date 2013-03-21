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
]

class SniffmypacketsEntity(Entity):
    namespace = 'sniffMyPackets'
    
 
class pcapFile(SniffmypacketsEntity):
    pass
    
class Interface(SniffmypacketsEntity):
    pass

@EntityField(name='sniffMyPackets.filelocation', propname='filelocation', displayname='File Location', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.rawdata', propname='rawdata', displayname='Raw Data', type=EntityFieldType.String)
class FileDump(SniffmypacketsEntity):
    pass
  
@EntityField(name='sniffMyPackets.getdst', propname='getdst', displayname='Dst IP & Port', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.getsrc', propname='getsrc', displayname='Src IP & Port', type=EntityFieldType.String)
class httpScan(SniffmypacketsEntity):
    pass
  
class UserLogin(SniffmypacketsEntity):
    pass