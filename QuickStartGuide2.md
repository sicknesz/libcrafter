# Introduction #

The heart of libcrafter are the `Send` and the `SendRecv` methods of the `Packet` class. Those methods will write on the network the packet that was assembled stacking a set of layers representing protocols in network the stack. But most important, libcrafter handles all the tedious work of packet crafting, like checksum calculations, lengths field calculations, the "next protocol" field on some layers, and so on.

So, if you aren't in the malformed-packet-crafting business, you just need to focus on the relevant fields of a protocol and let the library to do the tedious work you.

Of course, if you need to craft a packet with incorrect field values, you just have to explicitly set those fields and the library will stay out of your way.

# Basic example #

You can write whatever you want on the network. For example, put wireshark on with "not ip" as a filter expression on whatever interface you are using and execute the next program:

```
#include <iostream>
#include <string>
#include <crafter.h>

using namespace std;
using namespace Crafter;

int main() {
	/* Create the layer */
	RawLayer raw_layer("I'm using libcrafter to write this on the net. Cool, right?");

	/* Create the packet */
	Packet pck = raw_layer;

	/* Write that on the network */
	pck.Send("wlan0");

	return 0;
}
```

Compile the code and run the program (remember to change "wlan0" to yours interface):
```
$ g++ msg.cpp -o msg -lcrafter
$ sudo ./msg
```

On a switched environment, that packet won't go too far. But will be able to check it with wireshark:

![http://figures.libcrafter.googlecode.com/git/craftermsg.png](http://figures.libcrafter.googlecode.com/git/craftermsg.png)

As you can see, the string on the RawLayer was interpreted by wireshark as an Ethernet packet. Of course that makes no sense :-p.

But we are not here to write funny messages on the network, but to put together network packets that hopefully be useful for something.

# Ping! #

This code creates a simple ICMP echo request and send it to some destination.

```
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);                      // <-- Set a source IP address.
	ip_header.SetDestinationIP("www.google.com.ar");  // <-- Set a destination IP address as a domain name

	/* Create an ICMP header */
	ICMP icmp_header;

	icmp_header.SetType(ICMP::EchoRequest);        // <-- Echo request (a ping)
	icmp_header.SetIdentifier(RNG16());            // <-- Set a random ID for the ICMP packet

	/* Create a payload */
	RawLayer raw_header("HelloPing!\n");

	/* Create a packet... */
	Packet packet;

	/* ... and push each layer */
	packet.PushLayer(ip_header);
	packet.PushLayer(icmp_header);
	packet.PushLayer(raw_header);


	/* Print before sending */
	cout << endl << "[@] Print before sending: " << endl;
	packet.Print();

	/* Send the packet, this would fill the missing fields (like checksum, lengths, etc) */
	packet.Send(iface);

	/* Print after sending, the packet is not the same. */
	cout << endl << "[@] Print after sending: " << endl;
	packet.Print();

	return 0;

}
```

Compile the code and run the program:
```
$ g++ ping.cpp -o ping -lcrafter
$ sudo ./ping
```

You can catch the echo-reply from the server on a sniffer. The output on the console should be:
```
[@] Print before sending: 
< IP (20 bytes) :: Version = 4 , HeaderLength = 5 , DiffServicesCP = 0 , ExpCongestionNot = 0 , TotalLength = 0 , Identification = 0x0 , Flags = 2 , FragmentOffset = 0 , TTL = 64 , Protocol = 0x6 , CheckSum = 0x0 , SourceIP = 192.168.0.103 , DestinationIP = 74.125.45.94 , >
< ICMP (8 bytes) :: Type = 8 , Code = 0 , CheckSum = 0x0 , Identifier = 0x503b , SequenceNumber = 0x0 , >
< RawLayer (11 bytes) :: Payload = HelloPing!\n>

[@] Print after sending: 
< IP (20 bytes) :: Version = 4 , HeaderLength = 5 , DiffServicesCP = 0 , ExpCongestionNot = 0 , TotalLength = 39 , Identification = 0x0 , Flags = 2 , FragmentOffset = 0 , TTL = 64 , Protocol = 0x1 , CheckSum = 0x1ec , SourceIP = 192.168.0.103 , DestinationIP = 74.125.45.94 , >
< ICMP (8 bytes) :: Type = 8 , Code = 0 , CheckSum = 0xa912 , Identifier = 0x503b , SequenceNumber = 0x0 , >
< RawLayer (11 bytes) :: Payload = HelloPing!\n>
```

The output of the `Print()` function is quite intuitive. Each layer is printed along with the value of each of its fields. The package before being sent have some of their fields set with the default value. After the `Send()` function is called, those fields are filled by values ​​which depend on neighboring layers (checksums, length, next protocol, etc) on the packet.

Apart from print, you can "hexdump" a packet or print a raw hexadecimal string on STDOUT:

```
packet.HexDump()
```

will output:

```
  45000027 00004000 4001A5EB C0A80067  E..'..@.@......g 00000000
  4A7D895E 0800E85C 10F10000 48656C6C  J}.^...\....Hell 00000010
  6F50696E 67210A                      oPing!.          00000020
```

and

```
packet.RawString()
```

will output:

```
\x45\x0\x0\x27\x0\x0\x40\x0\x40\x1\xa5\xeb\xc0\xa8\x0\x67\x4a\x7d\x89\x5e\x8\x0\xe8\x5c\x10\xf1\x0\x0\x48\x65\x6c\x6c\x6f\x50\x69\x6e\x67\x21\xa
```

Keep in mind that `HexDump()` and `RawString()` aren't constants methods. Prior to "print" the packet to STDOUT both methods fill the missing fields in each of the layers. The effect is the same as calling `Send()`, except that nothing is written on the net.

# Ping Pong! #

Generally we are interested in matching packets we sent to the network (stimulus) with the correct receiving answers. For example, if I send to a destination IP address an UDP packet with a source port equal to 9876 to a destination port of 53, I expect an UDP packet from that IP in response from port 53 to port 9876. Or, alternatively, a Destination Unreachable ICMP message notifying me that the protocol or port are unreachable on the destination host. This job is done by the `SendRecv()` method.

The next example builds an ICMP echo-request, write it on the wire and waits for an answer. Finally, prints the response packet to STDOUT.

```
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);                   // <-- Set a source IP address.
	ip_header.SetDestinationIP("www.google.com");  // <-- Set a destination IP address as a domain name

	/* Create an ICMP header */
	ICMP icmp_header;

	icmp_header.SetType(ICMP::EchoRequest);        // <-- Echo request (a ping)
	icmp_header.SetIdentifier(RNG16());            // <-- Set a random ID for the ICMP packet

	/* Create a payload */
	RawLayer raw_header;
	raw_header.SetPayload("PingPongTest\n");

	/* Create a packet with the layers */
	Packet packet (ip_header / icmp_header / raw_header);

	/*
	 * If we send a PING (echo), we expect a PONG (reply).
	 * So, we use the SendRecv function.
	 */
	Packet *rcv = packet.SendRecv(iface);           // <-- If a reply is matched, the function
	                                                //     returns a pointer to that packet

	/* Check if the return value of SendRecv is not zero */
	if(rcv) {
		/* Print the packet */
		rcv -> Print();
		/* Delete the packet */
		delete rcv;
	} else
		cout << "[@] No answer... " << endl;

	return 0;

}
```

Compile and execute the program:

```
$ g++ pingpong.cpp -o pingpong -lcrafter
$ sudo ./pingpong
```

I get this on my console (MACs addresses are not shown):

```
< Ethernet (14 bytes) :: DestinationMAC = 1c:65:9d:*:*:* , SourceMAC = 00:1b:11:*:*:* , Type = 0x800 , >
< IP (20 bytes) :: Version = 4 , HeaderLength = 5 , DiffServicesCP = 0 , ExpCongestionNot = 0 , TotalLength = 41 , Identification = 0x977f , Flags = 0 , FragmentOffset = 0 , TTL = 45 , Protocol = 0x1 , CheckSum = 0x6160 , SourceIP = 74.125.137.104 , DestinationIP = 192.168.0.103 , >
< ICMP (8 bytes) :: Type = 0 , Code = 0 , CheckSum = 0x6189 , Identifier = 0x4ef5 , SequenceNumber = 0x0 , >
< RawLayer (13 bytes) :: Payload = PingPongTest\n>
```

As you can see, the library decodes the data coming from the net into a packet consisting of different layers of protocols (Ethernet, IP, ICMP and finally a RawLayer which carries a payload).

# Using your sockets #

Often you need to write packets on your sockets and the `Send` or `SendRecv` won't let you do that. That's why the `SocketSend` and `SocketSendRecv` functions were included in libcrafter.

In the next example, a packet socket is opened and binded to a interface on the main function. Then, the program makes a few calls to getMACaddr which is a function entirely programmed with libcrafter that performs and ARP request to find out the MAC address of some devices (the implementation could be on a different compilation unit).

```
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

string getMACaddr(int s, const string& iface, const string& ip_addr) {
	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);
	/* Get the MAC Address associated to the interface */
	string MyMAC = GetMyMAC(iface);

	Ethernet ether_header;

	ether_header.SetSourceMAC(MyMAC);
	ether_header.SetDestinationMAC("ff:ff:ff:ff:ff:ff");

	ARP arp_header;

	arp_header.SetOperation(ARP::Request);
        arp_header.SetSenderIP(MyIP);
        arp_header.SetSenderMAC(MyMAC);
	arp_header.SetTargetIP(ip_addr);

	Packet arp_pck = ether_header / arp_header;

	/* We use the socket provided */
	Packet* rcv = arp_pck.SocketSendRecv(s,iface);

	string ret = "";

	if(rcv) {
		ARP* arp_layer = rcv->GetLayer<ARP>();

		/* Get the MAC */
		ret = arp_layer->GetSenderMAC();

		delete rcv;
	}

	return ret;
}

int main() {

	/* Set the interface */
	string iface = "wlan0";

	int rawsock;

	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))== -1)
		exit(1);

	struct sockaddr_ll sll;
	struct ifreq ifr;

	memset(&sll,0,sizeof(sll));
	memset(&ifr,0,sizeof(ifr));

	/* First Get the Interface Index  */
	strncpy((char *)ifr.ifr_name, iface.c_str(), IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
	{
		perror("Getting Interface index");
		exit(1);
	}

	/* Bind our raw socket to this interface */
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);


	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
	{
		perror("Binding raw socket to interface");
		exit(1);
	}

	/* Get the MAC address of some IPs devices */
	cout << getMACaddr(rawsock,iface,"192.168.0.106") << endl;
	cout << getMACaddr(rawsock,iface,"192.168.0.1") << endl;

	close(rawsock);

	return 0;
}
```