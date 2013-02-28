# README - Sniffmypackets

This is a canari package for wireless auditing and discovery and some general packet goodness.

Uses scapy a lot for the packet sniffing and dissection. I've only tested this on BackTrack R3.

Requires that you manually set your wireless card into monitor mode (this may change later).

New entities will be installed under "sniffMyPackets". To get started set your wireless card in monitor mode.
I've been using "airmon-ng start [interface]

Add the monitor interface entity into a new Maltego graph. If the monitor interface is not mon0 (which is the default)
change the entity to match.

You will then be able to run 2 transforms, one looks for beacon frames and returns a list of Access Point entities.
The other one searches for clients by looking for Probe responses.

The transforms capture 500 packets, depending on the amount of traffic this can take some time to complete. From an access point
you can then pull out the channel information (which is stored in the entity) and from a client you can map them back to an
access point.

Any transform that has a "[U]" at the end means it will work when you are unauthenicated to the wireless network.

Coming soon:

[unauthenicated]
Change the number of packets it sniffs by setting a field in the monitorInterface entity
Perform deauth attacks
Sniffing for deauth packets and capturing wpa/wep handshakes
Sniff a client and look for probe requests belonging to other wireless networks previously connected to

[authenicated]
ARP scan to identify "live" clients
DNS capture to identify clients activity
Clear text password capture



