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
    'pcapFile',
    'pcapStream',
    'wiFiChannel',
    'WirelessCard',
    'Gateway',
    'Port'
]

class SniffmypacketsEntity(Entity):
    namespace = 'sniffMyPackets'
    
@EntityField(name='sniffMyPackets.count', propname='pktcount', displayname='Packet Count', type=EntityFieldType.Integer)
class monitorInterface(SniffmypacketsEntity):
    pass
  
@EntityField(name='sniffMyPackets.bssid', propname='apbssid', displayname='BSSID', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.channel', propname='apchannel', displayname='Channel', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.encryption', propname='apencryption', displayname='Encryption', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.apmoninterface', propname='apmoninterface', displayname='Monitor Interface', type=EntityFieldType.String)
class accessPoint(SniffmypacketsEntity):
    pass
  
@EntityField(name='sniffMyPackets.monInt', propname='monInt', displayname='Monitor Interface', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.clientSSID', propname='clientSSID', displayname='Client SSID', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.clientBSSID', propname='clientBSSID', displayname='Client BSSID', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.clientChannel', propname='clientChannel', displayname='Client BSSID', type=EntityFieldType.String)
class wifuClient(SniffmypacketsEntity):
    pass
  
class pcapFile(SniffmypacketsEntity):
    pass
  
class pcapStream(SniffmypacketsEntity):
  pass

class wiFiChannel(SniffmypacketsEntity):
    pass

class WirelessCard(SniffmypacketsEntity):
    pass

@EntityField(name='sniffMyPackets.gwmac', propname='GatewayMAC', displayname='Gateway MAC address', type=EntityFieldType.String)
@EntityField(name='sniffMyPackets.int2gw', propname='GatewayInt', displayname='Interface to Gateway', type=EntityFieldType.String)
class Gateway(SniffmypacketsEntity):
    pass


@EntityField(name='sniffMyPackets.portstate', propname='PortState', displayname='Port State', type=EntityFieldType.String, matching_rule=MatchingRule.Loose)
@EntityField(name='sniffMyPackets.srcport', propname='SrcPort', displayname='Src Port', type=EntityFieldType.String, matching_rule=MatchingRule.Loose)
class Port(SniffmypacketsEntity):
    pass
