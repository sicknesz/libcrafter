# Introduction #

Libcrafter is a high level library for C++ designed to make easier the creation and
decoding of network packets. It is able to craft or decode packets of most
common network protocols, send them on the wire, capture them and match
requests and replies.
It enables the creation of networking tools in a few lines with an interface
very similar to [Scapy](http://www.secdev.org/projects/scapy/).
A packet is  described as layers that you stack one upon the other. Fields of
each layer have useful default values that you can overload.

The library is designed to be used in multithreaded programs where you can
combine several tasks simultaneously. For example, you can easily design
something that sniffs, mangles, and sends at the same time you are doing
an ARP-Spoofing attack.
It also contains a very naive implementation of the TCP/IP stack (fragmentation
is no handled yet) at user level that enables working with TCP streams. This
makes easier the creation of tools for data injection on arbitrary connections, IP spoofing and TCP/IP session hijacking.

Libcrafter development is done on github:

https://github.com/pellegre/libcrafter

Testing and short-lived branches will be pushed there so users can follow libcrafter development.  Examples will be frequently updated on:

https://github.com/pellegre/libcrafter-examples

**Since Google Code no longer supports downloads for new projects I've move libcrafter downloads to google drive [here](https://drive.google.com/folderview?id=0B4PDTNA2TABgVWRSaW5yLW5UbFk&usp=sharing). You should get the latest version from there instead of the Download tabs**

# News #
  * 28/06/2014 - libcrafter version 0.3 released! Several minor fixes, improvements in the library performance and MAC OSX support. Thanks to all for the contributions! Please note that latest tarball is [here](https://drive.google.com/folderview?id=0B4PDTNA2TABgVWRSaW5yLW5UbFk&usp=sharing)
  * 19/06/2012 - libcrafter version 0.2 released! After getting a great feedback from some libcrafter users, this new version was developed with performance/efficiency in mind.
    * More protocols: Ethernet, SLL (Linux cooked-mode capture), ARP, DHCP, DHCP options, IP, IP options, IPv6, ICMP, ICMP extensions, TCP, TCP options, UDP and DNS.
    * Reading and dumping pcap files.
    * libcrafter no longer depends on libnet, and the packet injection is way more efficient than the last version. Also, now is possible to write libcrafter packets directly into raw or packet sockets.
    * Old code should compile with this new version but there are a few deprecated functions (a call to a deprecated function will print a warning on the screen). You should take a look to the examples to see the new features of the library. For example, there is no need to call InitCrafter and CleanCrafter anymore.
  * 12/06/2012 - Now libcrafter support IP and TCP options (328668d5804e). Very close to next release!
  * 07/06/2012 - I spend all the World IPv6 Day adding IPv6 support to libcrafter. Now it's done (681aff42286e).
  * 06/06/2012 - The current tree (d1a796397f3a) support pcap file format (reading and dumping).
  * 05/06/2012 - The current tree (0a7b124b5d00) now support SLL (pseudo) protocol (Linux cooked-mode capture)
  * 14/05/2012 - The current tree  now support ICMP extensions and MPLS extensions (248c2b1307a8) thanks to Bruno Nery contribution.
  * 29/04/2012 - The current tree now support the DHCP protocol (1184181f46a5).
  * 17/04/2012 - The current tree is now distributed under the New BSD license (1753ce8af7da).

# Installation #

The installation of the library in your system should be quite simple.
First download the latest release of the library from [here](https://drive.google.com/folderview?id=0B4PDTNA2TABgVWRSaW5yLW5UbFk&usp=sharing)

Extract the source code:

```
$ tar xfvz crafter-0.3.tar.gz
$ cd crafter-0.3
```
Before configuring and compiling libcrafter you need lipcap installed
in your system. On debian based distros, you should execute:

```
$ sudo apt-get install libpcap0.8 libpcap0.8-dev
```

Configure:

```
$ ./configure
```

Compile:

```
$ make
```

Install on your system:

```
$ sudo make install
$ sudo ldconfig
```

Finally, you can download some examples codes and test them:

```
wget http://libcrafter.googlecode.com/files/examples-0.2.tar.gz
```

If you want to use the cutting edge version (i.e. HEAD) of libcrafter you should you should have autoconf and libtool  installed in your system :

```
$ sudo apt-get install autoconf libtool
```

Clone the repository and compile the library :

```
$ git clone http://code.google.com/p/libcrafter/ # or git clone https://github.com/pellegre/libcrafter
$ cd libcrafter/libcrafter
$ ./autogen.sh 
$ make
$ sudo make install
$ sudo ldconfig
```

# Hello World! #

LibCrafter is best explained through examples. The following source code
shows a simple "Hello World" program:

```
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Create a Raw layer with some data on it... */
	RawLayer hello("Hello ");
	RawLayer world("World!");

	/* Create a packet to hold both layers */
	Packet packet = hello / world;

	/* You can print the packet in your screen in different formats */
	packet.Print();     /* Human-readable */
	packet.HexDump();   /* Machine-readable */
	packet.RawString(); /* A C hex string  */

	/* And last but not least, you can write the packet on the wire :-) */
	packet.Send("wlan0");

	return 0;
}
```

Compile the code (remember to change the interface name "wlan0" by yours),

```
$ g++ hello.cpp -o hello -lcrafter
```

And execute the program (you need root privileges):

```
$ sudo ./hello
```

If you put wireshark ON, you should catch a malformed ethernet packet with the "Hello World!" string on it:

![http://figures.libcrafter.googlecode.com/git/HelloWorld.png](http://figures.libcrafter.googlecode.com/git/HelloWorld.png)

# Simple TCP packet #

The next code craft a simple TCP packet with some arbitrary payload and write it on the wire. You can see how easy is to create and set the fields of a each protocol header (like IP and TCP in this example). Also note that you don't have to specify all the fields of a header (for example the program never set the checksum and the length field of the headers). Libcrafter is responsible to fill those values with the correct ones.

```
#include <iostream>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {
	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);
	cout << "[@] My IP address is  : " << MyIP  << endl;

	/* Create an IP header */
	IP ip_header;
	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);
	ip_header.SetDestinationIP("www.google.com");

	/* Create an TCP - SYN header */
	TCP tcp_header;
	tcp_header.SetSrcPort(11);
	tcp_header.SetDstPort(80);
	tcp_header.SetSeqNumber(RNG32());
	tcp_header.SetFlags(TCP::SYN);

	/* A raw layer, this could be any array of bytes or chars */
	RawLayer payload("ArbitraryPayload");

	/* Create a packets */
	Packet tcp_packet = ip_header / tcp_header / payload;

	cout << endl << "[@] Print before sending: " << endl;
	tcp_packet.Print();

	/* Write the packet on the wire */
	tcp_packet.Send();

	cout << endl << "[@] Print after sending: " << endl;
	tcp_packet.Print();

	return 0;
}
```

Compile the code (remember to change the interface name "wlan0" by yours),

```
$ g++ tcp.cpp -o tcp -lcrafter
```

And execute the program (you need root privileges):

```
$ sudo ./tcp
```

You should see something like this on your screen:

```
[@] My IP address is  : 192.168.0.103

[@] Print before sending: 
< IP (20 bytes) :: Version = 4 , HeaderLength = 5 , DiffServicesCP = 0 , ExpCongestionNot = 0 , TotalLength = 0 , Identification = 0x0 , Flags = 2 , FragmentOffset = 0 , TTL = 64 , Protocol = 0x6 , CheckSum = 0x0 , SourceIP = 192.168.0.103 , DestinationIP = 74.125.137.99 , >
< TCP (20 bytes) :: SrcPort = 28121 , DstPort = 80 , SeqNumber = 2777474608 , AckNumber = 0 , DataOffset = 5 , Reserved = 0 , Flags = ( SYN ) , WindowsSize = 5840 , CheckSum = 0x0 , UrgPointer = 0 , >
< RawLayer (16 bytes) :: Payload = ArbitraryPayload>

[@] Print after sending: 
< IP (20 bytes) :: Version = 4 , HeaderLength = 5 , DiffServicesCP = 0 , ExpCongestionNot = 0 , TotalLength = 56 , Identification = 0x0 , Flags = 2 , FragmentOffset = 0 , TTL = 64 , Protocol = 0x6 , CheckSum = 0xa5d0 , SourceIP = 192.168.0.103 , DestinationIP = 74.125.137.99 , >
< TCP (20 bytes) :: SrcPort = 28121 , DstPort = 80 , SeqNumber = 2777474608 , AckNumber = 0 , DataOffset = 5 , Reserved = 0 , Flags = ( SYN ) , WindowsSize = 5840 , CheckSum = 0xe7cd , UrgPointer = 0 , >
< RawLayer (16 bytes) :: Payload = ArbitraryPayload>

```

As you can see, before sending the packet there are some fields with values equal to zero. For example, the IP and TCP checksums are null and the data length field is also zero. But after sending the packet, all those fields are filled by the library with the correct values. Libcrafter handles all the tedious work of packet crafting and allows the programmer to concentrate on the most important thing: programming.

Of course, if the user set values to those fields the library preserves them to allow the creation of malformed packets to test the robustness of applications running on network devices.

# Documentation #

You should check first the Quick Start Guide:

[Introduction to libcrafter - Part 1 - Libcrafter basic](http://code.google.com/p/libcrafter/wiki/QuickStartGuide)

[Introduction to libcrafter - Part 2 - Building network packets with libcrafter](http://code.google.com/p/libcrafter/wiki/QuickStartGuide2)

[Introduction to libcrafter - Part 3 - Packet containers](http://code.google.com/p/libcrafter/wiki/QuickStartGuide3)

[Introduction to libcrafter - Part 4 - Introduction to the sniffer](http://code.google.com/p/libcrafter/wiki/SnifferIntroduction)

Then you should take a look to this tutorials and some simple implementations of common networking techniques:

> [1. ARP Network Ping](http://code.google.com/p/libcrafter/wiki/ARPPing)

> [2. ICMP Network Ping](http://code.google.com/p/libcrafter/wiki/ICMPPing)

> [3. Fast network scanning](http://code.google.com/p/libcrafter/wiki/FastPings)

> [4. Simple DNS Query](http://code.google.com/p/libcrafter/wiki/DNSQuery)

> [5. ARP Poison](http://code.google.com/p/libcrafter/wiki/ARPPoison)

> [6. TCP Traceroute](http://code.google.com/p/libcrafter/wiki/TCPTraceroute)

> [7. DNS Spoofing](http://code.google.com/p/libcrafter/wiki/DNSSpoofing)

I'm still working on a full documentation of the library and preparing some tutorials about TCP streams. Right now, the  best documentation are the header files of each class.

And most important, have fun!