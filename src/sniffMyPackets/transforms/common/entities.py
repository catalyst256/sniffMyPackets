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
    'monitorInterface',
    'accessPoints',
    'wifuClient',
    'pcapFile'
]

class SniffmypacketsEntity(Entity):
    namespace = 'sniffMyPackets'
    
#@EntityField(name='sniffMyPackets.fieldN', propname='fieldN', displayname='Field N', matchingrule=MatchingRule.Loose)
@EntityField(name='sniffMyPackets.count', propname='pktcount', displayname='Packet Count', type=EntityFieldType.Integer)
class monitorInterface(SniffmypacketsEntity):
    pass
  
@EntityField(name='sniffMyPackets.MAC', propname='macaddress', displayname='BSSID', type=EntityFieldType.String)
class accessPoint(SniffmypacketsEntity):
    pass
  
@EntityField(name='sniffMyPackets.monInt', propname='monInt', displayname='Monitor Interface', type=EntityFieldType.String)
class wifuClient(SniffmypacketsEntity):
    pass
  
class pcapFile(SniffmypacketsEntity):
    pass
  
class pcapStream(SniffmypacketsEntity):
  pass