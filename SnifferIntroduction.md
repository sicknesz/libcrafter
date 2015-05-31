# Introduction #

Besides packet generation capabilities, libcrafter also provides a class for sniffing packets from the network and decode them into a `Packet` object conformed by layers. Of course, not all protocols are implemented in the library. In case an unknown layer protocol is coming from the net, a RawLayer will be used. However, this is true for all application (layer 5) protocols  whether or not they are implemented in the library. There isn't a reliable way to know which protocol is coming on the top of an transport layer (is possible if we depend on values ​​of standard ports, which I think it not a safe thing to hardcode on the library). Ultimately, it is up to the user decode the application layers in the correct format.

The operation of the sniffer is quite simple: First you instantiate a sniffer object with some parameters: `Sniffer(const std::string& filter, const std::string& iface, PacketHandler HandlerFunction)`

  * `filter`: A filter expression in pcap format (like "tcp and dst port 87 and host 192.168.1.1") that selects which packets will be "captured".
  * `iface`: Network interface.
  * `HandlerFunction`: Is a function with the prototype:
```
  void HandlerFunction(Packet* sniff_packet, void* user)
```
> This function will be executed each time a packet is captured by the sniffer, which is referenced by the pointer in the first argument. The user void pointer is a generic pointer to some data structure provided by the user (in the following example should be clear how this function works). If this function is not provided to the constructor, by default, all captured packet will be printed on the standard output.

Once created, you can turn the sniffer on to begin capturing. There are two ways to do that:

  * `void Capture(uint32_t count = -1, void *user = 0)` : Begins to capture until the number of captured packets reaches `count`. If `count == -1` the sniffer captures _ad-infinitum_. The function blocks the program until all the packets are processed or until a signal is received. The `user` pointer is passed to the `HandlerFunction`.
  * `void Spawn(uint32_t count = -1, void *user = 0)` : Same as before except that the function returns immediately, leaving a thread in the background sniffing all the packets. This function is very useful when packet capture should be done in the background, combined with any other technique performed in the main thread.

If you spawn a sniffer with `Spawn(-1)`, you should shut it down by calling the `Cancel()` method.

# Simple example #

The next code captures the first five TCP packets with destination port equal to 80. If the captured packet have a payload, it is printed on the screen. If not, nothing is done, Probably, the printed payloads are HTTP traffic.

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

		cout << "[+] ------- [+]" << endl;
		/* Summarize some data */
		TCP* tcp_layer = sniff_packet->GetLayer<TCP>();
		cout << "[#] TCP packet from source port: " << tcp_layer->GetSrcPort() << endl;

		cout << "[#] With Payload: " << endl;
		/* You can get the payload as a string */
		string payload = raw_payload->GetStringPayload();
		cout << payload << endl;

	}
}


int main() {

	/* Set the interface */
	string iface = "wlan0";

	/*
	 * First, you should create a sniffer
	 * - 1st argument: Filter expression (tcpdump syntax)
	 * - 2nd argument: Interface
	 * - 3rd argument: A function that will be executed when a packet
	 * captured satisfies the filter expression (the default behavior is to
	 * print the packets to STDOUT).
	 */
	Sniffer sniff("tcp and port 22",iface,PacketHandler);

	/* Now, start the capture (five packets) */
	sniff.Capture(5);

	return 0;
}
```

Compile and run the code:

```
g++ sniff.cpp -o sniff -lcrafter
sudo ./sniff
```

I get this output on my screen (just finished writing "www.google.com.ar" in the browser):

```
[@] Using device: wlan0
[+] ------- [+]
[#] TCP packet from source port: 45398
[#] With Payload: 
GET / HTTP/1.1
Host: www.google.com.ar
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:11.0) Gecko/20100101 Firefox/11.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: PREF=ID=*********** AND HERE LIES A COOKIE **************************
*****************************************************************************
******************************** NOT SHOWN **********************************
```

# Spawn! #

Next example show how to spawn a sniffer on the background and do something else while the sniffer is capturing and processing the packets. In this case, the sniffer also captures TCP traffic with a destination port equal to 80 for 20 seconds,but saves the payloads (HTTP requests) to a file specified by the user. Meanwhile, the main thread prints a message on the screen every second (not very useful).

```
#include <iostream>
#include <fstream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

/* File stream */
ofstream file;

/* Function for handling a packet */
void PacketHandler(Packet* sniff_packet, void* user) {
	/* sniff_packet -> pointer to the packet captured */
	/* user -> void pointer to the data supplied by the user */

	/* Check if there is a payload */
	RawLayer* raw_payload = sniff_packet->GetLayer<RawLayer>();
	if(raw_payload) {

		file << "[+] ------- [+]" << endl;
		/* Summarize some data */
		TCP* tcp_layer = sniff_packet->GetLayer<TCP>();
		file << "[#] TCP packet from source port: " << tcp_layer->GetSrcPort() << endl;

		file << "[#] With Payload: " << endl;
		/* You can get the payload as a string */
		string payload = raw_payload->GetStringPayload();
		file << payload << endl;

	}
}


int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Open the file */
	file.open("http.dat");

	/*
	 * First, you should create a sniffer
	 * - 1st argument: Filter expression (tcpdump syntax)
	 * - 2nd argument: Interface
	 * - 3rd argument: A function that will be executed when a packet
	 * captured satisfies the filter expression (the default behavior is to
	 * print the packets to STDOUT).
	 */
	Sniffer sniff("tcp and dst port 80",iface,PacketHandler);

	/* Spawn the sniffer (ad-infinitum) */
	sniff.Spawn(-1);

	/* Estimated number of seconds */
	int nseconds = 20;
	for(int i = 0 ; i < nseconds ; i++) {
		cout << "[#] " << i << " seconds... " << endl;
		sleep(1);
	}

	/* Shut down cleanly the sniffer */
	sniff.Cancel();

	/* Close the file */
	file.close();

	return 0;
}
```

Compile and run the code while surfing the internet:

```
g++ spawn.cpp -o spawn -lcrafter
sudo ./spawn
```

I get this on my console:

```
[@] Using device: wlan0
[#] 0 seconds... 
[#] 1 seconds... 
[#] 2 seconds... 
[#] 3 seconds... 
.
.
.
[#] 16 seconds... 
[#] 17 seconds... 
[#] 18 seconds... 
[#] 19 seconds... 
```

If I run :

```
$ cat http.dat
```

I get a few of this requests:

```
[+] ------- [+]
[#] TCP packet from source port: 37179
[#] With Payload: 
GET /p/libcrafter/ HTTP/1.1
Host: code.google.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:11.0) Gecko/20100101 Firefox/11.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: PREF=ID=*********** AND HERE LIES A COOKIE **************************
*****************************************************************************
******************************** NOT SHOWN **********************************
```

Pretty easy, right?