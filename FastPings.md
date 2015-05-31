# Introduction #

The next code shows how to perform a fast network scan with ICMP or ARP.

The key lies in the fact that, after we send the stimulus, all the packets we expect from the network are of the same type. Therefore, we can put a sniffer on to start capturing the responses once we send all the requests packets (ARP requests or ICMP echo-requests) with the `Send()` function which is by far more faster than the `SendRecv()` function.

The next examples illustrate this concept.

# ARP Ping #

The next code is quite similar to the ARP ping example on a previous wiki [section](http://code.google.com/p/libcrafter/wiki/ARPPing). First a set of ARP requests are assembled and pushed on a container of packets. Then, using the Send function, all of them are sent to the network. Finally, responses are collected with a sniffer and the IP and MAC address of the alive hosts are printed on screen.

```
#include <iostream>
#include <string>
#include <map>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

map<string,string> pair_addr;

void PrintARPInfo(Packet* sniff_packet, void* user) {
	/* Get the ARP header from the sniffed packet */
	ARP* arp_layer = sniff_packet->GetLayer<ARP>();

	/* Get the Source IP / MAC pair */
	pair_addr[arp_layer->GetSenderIP()] = arp_layer->GetSenderMAC();

}

int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);
	/* Get the MAC Address associated to the interface */
	string MyMAC = GetMyMAC(iface);

	cout << "[@] My MAC address is : " << MyMAC << endl;
	cout << "[@] My IP address is  : " << MyIP  << endl;

	/* --------- Common data to all headers --------- */

	Ethernet ether_header;

	ether_header.SetSourceMAC(MyMAC);
	ether_header.SetDestinationMAC("ff:ff:ff:ff:ff:ff");   // <-- Set broadcast address

	ARP arp_header;

	arp_header.SetOperation(ARP::Request);                 // <-- Set Operation (ARP Request)
        arp_header.SetSenderIP(MyIP);                          // <-- Set our network data
        arp_header.SetSenderMAC(MyMAC);

    /* ---------------------------------------------- */

	/* Define the network to scan */
	vector<string> net = GetIPs("192.168.0.*");            // <-- Create a container of IP addresses from a "wildcard"
	vector<string>::iterator it_IP;                        // <-- Iterator

	/* Create a container to hold all the ARP requests */
	vector<Packet*> request_packets;

	/* Iterate to access each string that defines an IP address */
	for(it_IP = net.begin() ; it_IP != net.end() ; it_IP++) {

		arp_header.SetTargetIP(*it_IP);                    // <-- Set a destination IP address on ARP header

		/* Create a packet on the heap */
		Packet* packet = new Packet;

		/* Push the layers */
		packet->PushLayer(ether_header);
		packet->PushLayer(arp_header);

		/* Finally, push the packet into the container */
		request_packets.push_back(packet);
	}

	/* Create a sniffer for listen to ARP traffic of the network specified */
	Sniffer sniff("arp[7]=2",iface,PrintARPInfo);

	/* Spawn the sniffer, the function returns immediately */
	sniff.Spawn(-1);

	/*
	 * At this point, we have all the packets into the
	 * request_packets container. Now we can Send 'Em All.
	 */
	Send(request_packets.begin(), request_packets.end(), iface, 48);
	/* Give a second to the sniffer... */
	sleep(1);

	/* ... and close the sniffer */
	sniff.Cancel();

	/* Print the alive hosts */
	map<string,string>::iterator it_host;
	for(it_host = pair_addr.begin() ; it_host != pair_addr.end() ; it_host++)
		cout << "[@] Host " << (*it_host).first << " is up "
				"with MAC address " << (*it_host).second << endl;

	/* Delete the container with the ARP requests */
	vector<Packet*>::iterator it_pck;
	for(it_pck = request_packets.begin() ; it_pck < request_packets.end() ; it_pck++)
		delete (*it_pck);

	/* Print number of host up */
	cout << "[@] " << pair_addr.size() << " hosts up. " << endl;

	return 0;
}
```

Compile and run the code:

```
g++ arpping.cpp -o arpping -lcrafter
sudo ./arpping
```

I get this output on my console:

```
[@] My MAC address is : 1c:65:9d:0f:*:*
[@] My IP address is  : 192.168.0.100
[@] Using device: wlan0
[@] Host 192.168.0.1 is up with MAC address 14:d6:4d:26:*:*
[@] Host 192.168.0.101 is up with MAC address 08:00:27:28:*:*
[@] Host 192.168.0.102 is up with MAC address 08:00:27:a4:*:*
[@] 3 hosts up. 

real	0m0.455s
user	0m0.100s
sys	0m0.040s
```

In less than a second we scan the entire network. This is faster compared to the implementation on [this wiki section](http://code.google.com/p/libcrafter/wiki/ARPPing). Probably with only 255 hosts the timing isn't such a big deal but if you need to scan a huge network block, using `Send` + `Sniffer` instead of the `SendRecv` function can make the difference.

# ICMP Ping #

The next code is very similar to the ICMP scan done in [this wiki section](http://code.google.com/p/libcrafter/wiki/IMCPPing). We use the sniffer to capture the responses.

```
#include <iostream>
#include <vector>
#include <string>
#include <crafter.h>
#include <set>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

set<string> addr;

void PrintICMPInfo(Packet* sniff_packet, void* user) {

	/* Get the IP layer of the replied packet */
	IP* ip_layer = GetIP(*sniff_packet);

	/* Put the IP address into the set */
	addr.insert(ip_layer->GetSourceIP());

}

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
	vector<string> net = GetIPs("192.168.0.*");           // <-- Create a container of IP addresses from a "wildcard"
	vector<string>::iterator ip_addr;                     // <-- Iterator

	/* Create a PacketContainer to hold all the ICMP packets (is just a typedef for vector<Packet*>) */
	vector<Packet*> pings_packets;

	/* Iterate to access each string that defines an IP address */
	for(ip_addr = net.begin() ; ip_addr != net.end() ; ip_addr++) {

		ip_header.SetDestinationIP(*ip_addr);            // <-- Set a destination IP address
		icmp_header.SetIdentifier(RNG16());              // <-- Set a random ID for the ICMP packet

		/* Finally, push the packet into the container */
		pings_packets.push_back(new Packet(ip_header / icmp_header));
	}

	/* Create a sniffer for listen to ICMP traffic (only the replies) */
	Sniffer sniff("icmp and icmp[0:1]==0",iface,PrintICMPInfo);

	/* Spawn the sniffer, the function returns immediately */
	sniff.Spawn(-1);

	/*
	 * At this point, we have all the packets into the
	 * pings_packets container. Now we can Send 'Em All.
	 */
	Send(pings_packets.begin(), pings_packets.end(),iface,32);

	/* ... and close the sniffer */
	sniff.Cancel();

	/* Print the alive hosts */
	set<string>::iterator it_host;
	for(it_host = addr.begin() ; it_host != addr.end() ; it_host++)
		cout << "[@] Host " << (*it_host) << " up." << endl;

	/* Print the number of alive hosts */
	cout << "[@] " << addr.size() << " hosts up. " << endl;

	/* Delete the container with the requests */
	vector<Packet*>::iterator it_pck;
	for(it_pck = pings_packets.begin() ; it_pck < pings_packets.end() ; it_pck++)
		delete (*it_pck);

	/* Clean up library stuff */
	CleanCrafter();

	return 0;
}
```

Compile the code:

```
g++ netping.cpp -o netping -lcrafter
sudo ./netping
```

And execute it:

```
[@] My IP address is  : 192.168.0.100
[@] Using device: wlan0
[@] Host 192.168.0.1 up.
[@] Host 192.168.0.101 up.
[@] Host 192.168.0.102 up.
[@] 3 hosts up. 

real	0m0.795s
user	0m0.090s
sys	0m0.600s
```

Again, this method of scanning a network is much faster than the one presented on [this wiki section](http://code.google.com/p/libcrafter/wiki/IMCPPing).