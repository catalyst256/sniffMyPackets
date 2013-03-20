# README - Sniffmypackets

This is a canari package for pcap file analysis.

Uses scapy a lot for the packet sniffing and dissection. I've only tested this on BackTrack R3/Kali.

Currently focuses on TCP packets, will add others later.

You can either add pcap files manually using the pcapFile entity (under sniffMyPackets) or you can add an Interface and run a packet capture directly. 
Once you have a pcap file you run transforms to identify "TCP Talkers" which is based on the SYN flag being present in a packet.
From there you can then identify all IP's that the "Talker" has well talked to. You can then split those streams off into seperate pcap files.
There are currently transforms that will read a pcap file looking for HTTP traffic and dump the raw ASCII into an entity and text file. There is also a HTTP Scan transform
that will search a pcap file and return a list of HTTP GET requests, this will dump to a text file (maybe an entity).

[Coming Soon]
Will look at pulling out artifacts, such as exe files, images, etc. etc.
Clear text password grabbing
Email/attachment rebuild 


