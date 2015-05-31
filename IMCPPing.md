# Introduction #

The next code send an "echo" ICMP packet to a set of hosts (in this case, to every host of the `10.0.1.*` network). First the packets to be send are assembled and stored in a packet container. Then, using the SendRecv function we send the entire container in one line.

# Code #

We have a new function in this code:

  * `vector<string> GetIPs(const string& argv)` : The function takes as argument a set of IPs addresses defined as a "wildcard". For example, `"192.168.1.*"`, `"192.168.4.1-23"`, `"192.168.1.1,10,65"` and so on (nmap style). The function returns a pointer to a vector of strings that contains IP addresses defined by the wildcard. For example, the following code:
```
  /* Define the network to scan */
  vector<string> net = ParseIP("192.168.1.*");        // <-- Create a container of IP addresses from a "wildcard"
  vector<string>::iterator ipaddr;                    // <-- Iterator

  /* Iterate to access each string that defines an IP address */
  for(ipaddr = net->begin() ; ipaddr != net->end() ; ipaddr++) 
      cout << (*ipaddr) << endl;
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

In short, the program send echo-request packets to each one of the hosts defined by the wildcard `"10.0.1.*"`. Finally prints to STDOUT the IP address of the hosts that respond the request.

```
/*
 * Ping Scan *
 * This program performs a ping scan on a network specified by the user.
 */
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
	vector<string> net = GetIPs("192.168.0.*");    // <-- Create a container of IP addresses from a "wildcard"
	vector<string>::iterator it_IP;                      // <-- Iterator

	/* Create a container of pointers to packets to hold all the ICMP packets */
	vector<Packet*> pings_packets;

	/* Iterate to access each string that defines an IP address */
	for(it_IP = net.begin() ; it_IP != net.end() ; it_IP++) {

		ip_header.SetDestinationIP(*it_IP);              // <-- Set a destination IP address
		icmp_header.SetIdentifier(RNG16());              // <-- Set a random ID for the ICMP packet

		/* Finally, push the packet into the container */
		pings_packets.push_back(new Packet(ip_header / icmp_header));
	}

	/*
	 * At this point, we have all the packets into the
	 * pings_packets container. Now we can Send 'Em All.
	 *
	 * 48 (nthreads) -> Number of threads for distributing the packets
	 *                  (tunable, the best value depends on your
	 *                   network an processor).
	 * 0.1 (timeout) -> Timeout in seconds for waiting an answer
	 * 2  (retry)    -> Number of times we send a packet until a response is received
	 */
	cout << "[@] Sending the ICMP echoes. Wait..." << endl;

	/* Create a packet container to hold all the answers */
	vector<Packet*> pongs_packets(pings_packets.size());
	SendRecv(pings_packets.begin(),pings_packets.end(),pongs_packets.begin(),iface,0.1,2,48);

	cout << "[@] SendRecv function returns :-) " << endl;

	/*
	 * pongs_packets is a pointer to a PacketContainer with the same size
	 * of pings_packets (first argument). So, at this point, (after
	 * the SendRecv functions returns) we can iterate over each
	 * reply packet, if any.
	 */
	vector<Packet*>::iterator it_pck;
	int counter = 0;
	for(it_pck = pongs_packets.begin() ; it_pck < pongs_packets.end() ; it_pck++) {
		/* Check if the pointer is not NULL */
		Packet* reply_packet = (*it_pck);
		if(reply_packet) {
            /* Get the ICMP layer */
            ICMP* icmp_layer = reply_packet->GetLayer<ICMP>();
            if(icmp_layer->GetType() == ICMP::EchoReply) {
				/* Get the IP layer of the replied packet */
				IP* ip_layer = reply_packet->GetLayer<IP>();
				/* Print the Source IP */
				cout << "[@] Host " << ip_layer->GetSourceIP() << " up." << endl;
				counter++;
            }
		}
	}

	cout << "[@] " << counter << " hosts up. " << endl;

	/* Delete the container with the requests */
	for(it_pck = pings_packets.begin() ; it_pck < pings_packets.end() ; it_pck++)
		delete (*it_pck);

	/* Delete the container with the responses  */
	for(it_pck = pongs_packets.begin() ; it_pck < pongs_packets.end() ; it_pck++)
		delete (*it_pck);

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

real	0m4.793s
user	0m0.060s
sys	0m0.750s
```