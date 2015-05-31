# Introduction #

Generally we are interested in matching packets we sent to the network (stimulus) with the correct receiving answers. For example, if I send to some destination an UDP packet with a source port equal to 9876 to a destination port equal to 53, I expect an UDP packet in response from port 53 to port 9876. Or, alternatively, a Destination Unreachable ICMP message notifying me that the protocol or port are unreachable on the destination host.

This job is done by the `SendRecv()` method. The function prototype with their respective arguments by default is:

`Packet* SendRecv(const std::string& iface = "", int timeout = 5, int retry = 3, const std::string& user_filter = " ")`

The function returns a pointer to a response packet allocated on the heap. It's user's responsibility to delete it after being used. If no matching answer comes from the net, the function returns a null pointer. It is also user's responsibility to check the return value of this function.

  * `iface` : Network interface. `"wlan0"`, `"eth0"`, etc.
  * `timeout` : Can be assigned a time in seconds after which the function will stop waiting for answers.
  * `retry` : Fixes the maximum number of times a packet can be sent. The packet that is unanswered after the first round will be sent again in another round, and again and again until it is answered or the number of sending reaches the value of retry. The timeout parameter is used every round.
  * `user_filter` : By default, the library will try to do the best for matching a packet with an answer. Of course, programmers are human and can make mistakes. If the package returned by the function does not satisfy you, you can set the filter (in tcpdump syntax) to match an answer from the net.

# Simple Ping Pong #

The next code forge an ICMP echo-request, write it on the wire and waits for an answer. Finally, prints the response packet to STDOUT.

```
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Init the library */
	InitCrafter();

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);                   // <-- Set a source IP address.
	ip_header.SetDestinationIP("www.github.com");  // <-- Set a destination IP address as a domain name

	/* Create an ICMP header */
	ICMP icmp_header;

	icmp_header.SetType(ICMP::EchoRequest);        // <-- Echo request (a ping)
	icmp_header.SetIdentifier(RNG16());            // <-- Set a random ID for the ICMP packet

	/* Create a payload */
	RawLayer raw_header;
	raw_header.SetPayload("PingPongTest\n");

	/* Create a packet... */
	Packet packet;

	/* ... and push each layer */
	packet.PushLayer(ip_header);
	packet.PushLayer(icmp_header);
	packet.PushLayer(raw_header);

	/*
	 * If we send a PING (echo), we expect a PONG (reply).
	 * So, we use the SendRecv function.
	 */
	Packet *rcv = packet.SendRecv(iface,2);         // <-- If a reply is matched, the function
	                                                //     returns a pointer to that packet

	/* Check if the return value of SendRecv is not zero */
	if(rcv) {
		/* Print the packet */
		rcv -> Print();
		/* Delete the packet, it's your responsibility */
		delete rcv;
	} else
		cout << "[@] No answer... " << endl;

	/* Clean before exit */
	CleanCrafter();

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
< Ethernet (14 bytes) :: Destination = 1c:65:9d:*:*:* ; Source = 94:0c:6d:*:*:* ; Type = 800 ; Payload = >
< IP (20 bytes) :: CheckSum=0x9e43 ; DestinationIP=10.0.1.100 ; DifSerCP=0 ; Identification=0x28d8 ; 
Off=(Flags=0,FragmentOffset=0) ; Protocol=0x1 ; SourceIP=207.97.227.243 ; TTL=53 ; TotalLength=41 ; 
VerHdr=(Version=4,HeaderLength=5) ; Payload = >
< ICMP (8 bytes) :: CheckSum=0x497a ; Code=0 ; Identifier=0x6704 ; SequenceNumber=0x0 ; Type=0 ; Payload = >
< RawLayer (13 bytes) :: Payload = PingPongTest\n>
```

As you can see, the library decodes the data coming from the net into a packet consisting of different layers of protocols (Ethernet, IP, ICMP and finally a RawLayer which carries a payload). You can always check with a sniffer if the data interpreted by the library is correct.


# Network Ping Pong #

The next code send an "echo" ICMP packet to a set of hosts (in this case, to every host of the `10.0.1.*` network). First the packets to be send are assembled and stored in a packet container. Then, using the SendRecv function (which is not the same presented above) we send the entire container in one line.

We have a few new things in this code:

  * `PacketContainer`: It is just a typedef for `std::vector<Packet*>`.

  * `std::vector<std::string>* ParseIP(const std::string& argv)` : The function takes as argument a set of IPs addresses defined as a "wildcard". For example, `"192.168.1.*"`, `"192.168.4.1-23"`, `"192.168.1.1,10,65"` and so on (nmap style). The function returns a pointer to a vector of strings that contains IP addresses defined by the wildcard. For example, the following code:
```
  /* Define the network to scan */
  vector<string>* net = ParseIP("192.168.1.*");        // <-- Create a container of IP addresses from a "wildcard"
  vector<string>::iterator it_IP;                      // <-- Iterator

  /* Iterate to access each string that defines an IP address */
  for(it_IP = net->begin() ; it_IP != net->end() ; it_IP++) 
      cout << (*it_IP) << endl;

  /* Delete the IP address container */
  delete net;
```
> will produce the output:
```
  192.168.1.0
  192.168.1.1
  192.166.1.2
  .
  .
  .
  192.168.1.256
```

  * `PacketContainer* SendRecv(PacketContainer* PacketContainer, const string& iface,int num_threads, int timeout, int retry)` : As you can see in the code below, this is a function and not a class method. Apart from that, the behavior is similar to the `Packet::SendRecv` function except for:
    * The first argument is a packet container and the function will send each of the packets on it.
    * The return value is another `PacketContainer` with the same length as the one of the first argument. There is a one to one correspondence between the two containers. If a particular packet produces no answer, a null pointer will be set on the return container.
    * We have a new parameter: `num_threads`. It is the number of threads  in which the packets to be sent are distributed. This operation has a high latency, so you can benefit from using many threads (more than the amount of physical cores). In my Intel-i7 processor, 48 threads is often a good number.

  * `ICMP* GetICMP(const Packet& packet)` and `IP* GetIP(const Packet& packet)` functions: Both functions get a constant reference of a packet as an argument and return a pointer to the first occurrence of the respective layer on the packet. If there isn't an IP layer, the function GetIP will return a null pointer (is the user's responsibility to check the returned value). There are similar functions for each implemented protocol of layers 2, 3 and 4 (`GetEthernet`, `GetARP`, `GetUDP`, and so on). If there is more than one layer of the same type in a packet, you should use layers iterators to access them. Later I'll show examples of layers iterators...

In short, the program send echo-request packets to each one of the hosts defined by the wildcard `"10.0.1.*"`. Finally prints to STDOUT the IP address of the hosts that respond the request.

```
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Init the library */
	InitCrafter();

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);
	cout << "[@] My IP address is  : " << MyIP  << endl;

	/* --------- Common data to all headers --------- */

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);                         // <-- Set a source IP address.

	/* Create an ICMP header */
	ICMP icmp_header;

	icmp_header.SetType(ICMP::EchoRequest);              // <-- Echo request (a ping)
	icmp_header.SetPayload("ThisIsThePayloadOfAPing\n"); // <-- Set an arbitrary payload

    /* ---------------------------------------------- */

	/* Define the network to scan */
	vector<string>* net = ParseIP("10.0.1.*");           // <-- Create a container of IP addresses from a "wildcard"
	vector<string>::iterator it_IP;                      // <-- Iterator

	/* Create a PacketContainer to hold all the ICMP packets (is just a typedef for vector<Packet*>) */
	PacketContainer pings_packets;

	/* Iterate to access each string that defines an IP address */
	for(it_IP = net->begin() ; it_IP != net->end() ; it_IP++) {

		ip_header.SetDestinationIP(*it_IP);          // <-- Set a destination IP address
		icmp_header.SetIdentifier(RNG16());          // <-- Set a random ID for the ICMP packet

		/* Create a packet on the heap */
		Packet* packet = new Packet;

		/* Push the layers */
		packet->PushLayer(ip_header);
		packet->PushLayer(icmp_header);

		/* Finally, push the packet into the container */
		pings_packets.push_back(packet);
	}

	/*
	 * At this point, we have all the packets into the
	 * pings_packets container. Now we can Send 'Em All.
	 *
	 * 48 (nthreads) -> Number of threads for distributing the packets
	 *                  (tunneable, the best value depends on your
	 *                   network an processor). 
	 * 1  (timeout)  -> Timeout in seconds for waiting an answer
	 * 2  (retry)    -> Number of times we send a packet until a response is received
	 */
	cout << "[@] Sending the ICMP echoes. Wait..." << endl;
	PacketContainer* pongs_packets = SendRecv(&pings_packets,iface,48,1,2);
	cout << "[@] SendRecv function returns :-) " << endl;

	/*
	 * pongs_packets is a pointer to a PacketContainer with the same size
	 * of pings_packets (first argument). So, at this point, (after
	 * the SendRecv functions returns) we can iterate over each
	 * reply packet, if any.
	 */
	PacketContainer::iterator it_pck;
	int counter = 0;
	for(it_pck = pongs_packets->begin() ; it_pck < pongs_packets->end() ; it_pck++) {
		/* Check if the pointer is not NULL */
		Packet* reply_packet = (*it_pck);
		if(reply_packet) {
                   /* Get the ICMP layer */
                   ICMP* icmp_layer = GetICMP(*reply_packet);
                   /* Check if the ICMP packet is an echo-reply */
                   if(icmp_layer->GetType() == ICMP::EchoReply) {
			/* Get the IP layer of the replied packet */
			IP* ip_layer = GetIP(*reply_packet);
			/* Print the Source IP */
			cout << "[@] Host " << ip_layer->GetSourceIP() << " up." << endl;
			counter++;
                   }
		}
	}

	cout << "[@] " << counter << " hosts up. " << endl;

	/* Now, because we are good programmers, clean everything before exit */

	/* Delete the container with the PINGS packets */
	for(it_pck = pings_packets.begin() ; it_pck < pings_packets.end() ; it_pck++)
		delete (*it_pck);

	/* Delete the container with the reponses, if there is one (check the NULL pointer) */
	for(it_pck = pongs_packets->begin() ; it_pck < pongs_packets->end() ; it_pck++)
		if((*it_pck)) delete (*it_pck);

	/* Delete the container itself */
	delete pongs_packets;

	/* Delete the IP address container */
	delete net;

	/* Clean up library stuff */
	CleanCrafter();

	return 0;
}
```

Compile and run the program:

```
$ g++ netping.cpp -o netping -lcrafter
$ time sudo ./netping
```

The output on my console is:

```
$ time sudo ./netping 
[@] My IP address is  : 10.0.1.100
[@] Sending the ICMP echoes. Wait...
[@] SendRecv function returns :-) 
[@] Host 10.0.1.101 up.
[@] Host 10.0.1.102 up.
[@] Host 10.0.1.105 up.
[@] 3 hosts up. 

real	0m13.464s
user	0m0.250s
sys	0m1.570s
```

If I do the same scan with nmap I get:

```
$ time nmap -nvvsP 10.0.1.*

Starting Nmap 5.21 ( http://nmap.org ) at 2012-03-21 03:12 WARST
Initiating Ping Scan at 03:12
Scanning 256 hosts [2 ports/host]
Completed Ping Scan at 03:13, 6.15s elapsed (256 total hosts)
Nmap scan report for 10.0.1.0 [host down]
Nmap scan report for 10.0.1.1 [host down]
.
.
.
Nmap scan report for 10.0.1.101
Host is up (0.013s latency).
Nmap scan report for 10.0.1.102
Host is up (0.032s latency).
Nmap scan report for 10.0.1.103 [host down]
Nmap scan report for 10.0.1.104 [host down]
Nmap scan report for 10.0.1.105
Host is up (0.0012s latency).
Nmap scan report for 10.0.1.106 [host down]
Nmap scan report for 10.0.1.107 [host down]
.
.
.
Nmap scan report for 10.0.1.254 [host down]
Nmap scan report for 10.0.1.255 [host down]
Nmap done: 256 IP addresses (3 hosts up) scanned in 6.15 seconds

real	0m6.163s
user	0m0.070s
sys	0m0.000s
```

As you can see, even with the level of abstraction of the library, performance is not so bad but still is quite poor. Later I'll show you a method by which this scan can be done in less than a second :-)

As a reference, there is also the function `Send ()` to send a packet container but does not expect any response from them. The arguments and behavior are equal to the function `SendRecv()`:

`void Send(PacketContainer* PacketContainer, const std::string& iface = "", int num_threads = 16)`

# Customized filters #

As formerly mentioned, you can provide a customized filter for matching a response to a sent packet. When the crafted packet makes "no sense" (at least for normal people) the SendRecv will return immediately printing some disturbing warnings messages. Most of them are because you are trying to craft a strange/weird/nonsense packet (like the one in the next example), and some data (for example, the UDP or TCP checksum) cannot be calculated and the library has no information on how to match that packet. You can suppress those warnings calling `Verbose(0)` at the beginning.

If you want to "catch" a response, you should call `SendRecv()` with a pcap/tcpdump filter expression as a third argument. So the function will block until a packet that matches that filter expression is captured.  In the next example I wait for a packet that satisfies the expression "tcp and src port 80".

This could be a workaround if the `SendRecv()` method does not work properly due to a programming bug or to handle unimplemented protocols.

```
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Init the library */
	InitCrafter();

	//Verbose(0);

	/* Set the interface */
	string iface="wlan0";

	/* Create an Ethernet layer */
	Ethernet ether_header;

	ether_header.SetDestinationMAC("ff:ff:ff:ff:ff:ff");
	ether_header.SetSourceMAC("aa:bb:cc:dd:ee:ff");

	/* Create an ARP layer */
	ARP arp_header;

	arp_header.SetSenderIP("3.3.3.3");
	arp_header.SetTargetIP("4.4.4.4");

	/* Create a IP layer */
	IP ip_header;

	ip_header.SetDestinationIP("1.1.1.1");
	ip_header.SetSourceIP("2.2.2.2");
	ip_header.SetTTL(6);
	ip_header.SetIdentification(RNG16());

	/* Create a ICMP layer */
	ICMP icmp_header;

	icmp_header.SetType(ICMP::DestinationUnreachable);

	/* Create an UDP layer */
	UDP udp_header;

	udp_header.SetDstPort(RNG16());
	udp_header.SetSrcPort(RNG16());

	/* Create a raw_layer with some random data */
	RawLayer raw_header("This is some random data");

	/* [+] Let craft one non-sense packet! :-) */

	Packet packet;

	/* Now, push the UDP layer... */
	packet.PushLayer(udp_header);
	/* ... then the ICMP layer. */
	packet.PushLayer(icmp_header);
	/* Now the payload... */
	packet.PushLayer(raw_header);
	/* Finally the IP and ARP layers... */
	packet.PushLayer(ip_header);
	packet.PushLayer(arp_header);
	/* ... and on the top of the packet, why not, an Ethernet layer :-) */
	packet.PushLayer(ether_header);

	/* This is one hell of a packet... */

	/*
	 * The packet is going to be written on the wire, but don't expect any answer...
	 * The library doesn't know how to match a response of this weird packet.
	 */
	Packet *rcv = packet.SendRecv(iface,2,2);   // <-- This call writes the packet on the wire
	                                            //     but doesn't wait for any answer

	/*
	 * If you want to "catch" a response, you should call SendRecv
	 * with a tcpdump filter expression as a third argument.
	 * So, the function will block until a packet that match that filter
	 * expression is captured.
	 */
	rcv = packet.SendRecv(iface,2,2,"tcp and src port 80");

	/* Check if the return value of SendRecv is not zero */
	if(rcv) {
		/* Print the packet */
		rcv -> Print();
		/* Delete the packet, is your responsibility */
		delete rcv;
	} else
		cout << "[@] No answer... " << endl;

	/* Clean before exit */
	CleanCrafter();

	return 0;

}
```

Compile the code:

```
g++ nonsense.cpp -o nonsense -lcrafter
sudo ./nonsense
```

And execute the program... I get this on my console (I was just downloading something from fileserve.com :-P):

```
[!] WARNING  : Packet::SendRecv() -> The first layer in the stack (UDP) is not IP or Ethernet and you didn't supply a filter expression. Don't expect any answer.
[!] WARNING  : Ethernet::Craft() -> No Network Layer Protocol associated with Ethernet Layer.
[!] WARNING  : UDP::Craft() -> Top Layer of UDP packet is not IP. Cannot calculate UDP checksum.
[!] WARNING  : Packet::SendRecv() -> The first layer in the stack (UDP) is not IP or Ethernet.
[!] WARNING  : Ethernet::Craft() -> No Network Layer Protocol associated with Ethernet Layer.
[!] WARNING  : UDP::Craft() -> Top Layer of UDP packet is not IP. Cannot calculate UDP checksum.
< Ethernet (14 bytes) :: Destination = 1c:65:9d:0f:30:4b ; Source = 14:d6:4d:26:7a:7c ; Type = 800 ; Payload = >
< IP (20 bytes) :: CheckSum=0xa642 ; DestinationIP=192.168.0.100 ; DifSerCP=0 ; Identification=0x716b ; Off=(Flags=2,FragmentOffset=0) ; Protocol=0x6 ; SourceIP=199.91.153.14 ; TTL=60 ; TotalLength=1492 ; VerHdr=(Version=4,HeaderLength=5) ; Payload = >
< TCP (32 bytes) :: AckNumber=883926398 ; CheckSum=0x9de ; DstPort=50067 ; Flags=( ACK ) ; OffRes=(DataOffset=8,Reserved=0) ; SeqNumber=1682334304 ; SrcPort=80 ; WindowsSize=54 ; Payload = \x1\x1\x8\xa\xab\x13\xbe\xad\x0\x6b\xbc\x6b>
< RawLayer (1440 bytes) :: Payload = \xdd\xdf\x20\x5a\x5\x16\x11\x76\x2c\xe8\x65\x1d..............
```

In total 6 warnings appear on the screen. The first three are for the first call of the `SendRecv()` function and the last 3 for the second one.

  * When we call the function without the filter expression, the library warns:

> _"The first layer in the stack (UDP) is not IP or Ethernet and you didn't supply a filter expression. Don't expect any answer."_

> In this case, the function returns immediately and a NULL pointer is returned.

  * When we call the function with the filter expression as a third argument, the function blocks until a packet with that pattern is matched. In this case, the library warns:

> _"The first layer in the stack (UDP) is not IP or Ethernet"_

> Probably, on a switched environment, that packet won't go too far.

The other two warnings are common to both function calls and the library is complaining about the arrangement of the layers in the packet (can't calculate checksum and can't set the protocol field on the Ethernet header).

[Next Recommended Tutorial : ARP Ping](http://code.google.com/p/libcrafter/wiki/ARPPing)