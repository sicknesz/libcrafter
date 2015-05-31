# Introduction #

DNS is a layer 5 protocol and its implementation is not as straightforward as the other protocols. A DNS layer contains a fixed set of data on the header, and a payload consisting of an arbitrary number of DNS Queries and Resource Records. You should read the RFC 1035 for more information.

For purposes of the library, the DNS layer consists of a series of fixed fields inside a header and four containers (STL vectors): one container for Queries and the other three for the Answer, Authority and Additional Section all comprise Resource Records (RRs) and hence share the same format.

The use of the DNS layer is complemented with two extra classes:

  * `DNS::DNSQuery` : Class for Queries
  * `DNS::DNSAnswer` : Class for Resource Records (3 last sections).

An additional method of the DNS class is provided to fill the fields of the header and fill the different sections extracting the information from a RawLayer.

# DNS Query Code #

The next code illustrate the use of the DNS class to send a DNS query to a DNS server.

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
	string dns_server = "192.168.0.1";

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);
	ip_header.SetDestinationIP(dns_server);

	/* Create a UDP header */
	UDP udp_header;

	/* Set the source and destination ports */
	udp_header.SetSrcPort(RNG16());
	udp_header.SetDstPort(53);

	/* Create a DNS layer */
	DNS dns_header;

	/* Set a random ID */
	dns_header.SetIdentification(RNG16());

	/* Create a DNSQuery class. This class IS NOT a <Layer> class */
	DNS::DNSQuery dns_query("www.google.com");
	/* Set the type */
	dns_query.SetType(DNS::TypeA);

	/* Push the query into a container inside the DNS header */
	dns_header.Queries.push_back(dns_query);

	/* Create a packet... */
	Packet packet = ip_header / udp_header / dns_header;

	/* Send and wait for an answer */
	Packet* rcv = packet.SendRecv(iface);

	if(rcv) {
		/*
		 * An application protocol is always get from the network as a raw layer. There is
		 * no way to know which protocol is on the top of a transport layer (unless we rely on
		 * standard ports numbers, which is not always the case).
		 */
		DNS dns_rcv;
		/* Fill the DNS layer information from a raw layer */
		dns_rcv.FromRaw(*(rcv->GetLayer<RawLayer>()));
		/* Finally print the response to STDOUT */
		dns_rcv.Print();
		/* Delete the received packet */
		delete rcv;
	} else
		cout << "[@] No response from DNS server" << endl;

	return 0;
}
```

Compile and run the program:

```
g++ dnsquery.cpp -o dnsquery -lcrafter
sudo ./dnsquery
```

The response of the server is:

```
< DNS (268 bytes) :: Identification = 0x3a69 , QRFlag = 1 (Response) , OpCode = 0 , AAFlag = 0 , TCFlag = 0 , RDFlag = 0 , RAFlag = 1 , ZFlag = 0 , ADFlag = 0 , CDFlag = 0 , RCode = 0 , TotalQuestions = 1 , TotalAnswer = 7 , TotalAuthority = 0 , TotalAdditional = 0 , Payload = 
  < Query (20 bytes) :: QName = www.google.com ; Type = 0x1 ; Class = 0x1 > 
  < Answer (44 bytes) :: QName = www.google.com ; Type = 0x5 ; Class = 0x1 ; TTL = 0x73a08 ; RDataLength = 18 ; RData = www.l.google.com > 
  < Answer (32 bytes) :: QName = www.l.google.com ; Type = 0x1 ; Class = 0x1 ; TTL = 0xe4 ; RDataLength = 4 ; RData = 74.125.137.104 > 
  < Answer (32 bytes) :: QName = www.l.google.com ; Type = 0x1 ; Class = 0x1 ; TTL = 0xe4 ; RDataLength = 4 ; RData = 74.125.137.105 > 
  < Answer (32 bytes) :: QName = www.l.google.com ; Type = 0x1 ; Class = 0x1 ; TTL = 0xe4 ; RDataLength = 4 ; RData = 74.125.137.106 > 
  < Answer (32 bytes) :: QName = www.l.google.com ; Type = 0x1 ; Class = 0x1 ; TTL = 0xe4 ; RDataLength = 4 ; RData = 74.125.137.147 > 
  < Answer (32 bytes) :: QName = www.l.google.com ; Type = 0x1 ; Class = 0x1 ; TTL = 0xe4 ; RDataLength = 4 ; RData = 74.125.137.99 > 
  < Answer (32 bytes) :: QName = www.l.google.com ; Type = 0x1 ; Class = 0x1 ; TTL = 0xe4 ; RDataLength = 4 ; RData = 74.125.137.103 > 
>
```