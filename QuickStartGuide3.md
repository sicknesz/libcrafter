# Container of packets #

Currently, libcrafter offer an interface to send and match a collection of packets (pointers) stored on STL **sequence** containers (std::vector, std::list and std::deque). The collections of functions especially designed to be used on ranges of packets, operate through iterators to containers of packet pointers. The pointers can be smart ones (like `boost:shared_ptr<Packet>` or `tr1::shared_ptr<Packet>`) or normal ones (`Packet*`).

  * `void Send(FowardIter begin, FowardIter end, const string& iface = "", int num_threads = 0)`
  * `void SocketSend(int sd, FowardIter begin, FowardIter end, int num_threads = 0)`
  * `SendRecv(FowardIter begin, FowardIter end, OutputIter out_begin, const string& iface = "", double timeout = 1, int retry = 3, int num_threads = 0)`
  * `SocketSendRecv(int sd, FowardIter begin, FowardIter end, OutputIter out_begin, const string& iface = "", double timeout = 1, int retry = 3, int num_threads = 0)`

The best way to explain the above functions is through examples. Lets craft 3 packets and put them into a "packet container":

```
string iface = "wlan0";

IP ip;
ip.SetSourceIP(GetMyIP(iface));
ip.SetDestinationIP("1.2.3.4");
	
vector<Packet*> pck_cont;

pck_cont.push_back(new Packet(ip / UDP() / RawLayer("UDPData")));
pck_cont.push_back(new Packet(ip / TCP() / RawLayer("TCPData")));
pck_cont.push_back(new Packet(ip / ICMP() / RawLayer("ICMPData")));
```

Using the `Send` function, we can Send 'Em All in one call:

```
Send(pck_cont.begin(),pck_cont.end());
```

And at the end of the program, you should delete all the packets created:

```
vector<Packet*>::iterator it_pck;
for(it_pck = pck_cont.begin() ; it_pck != pck_cont.end() ; it_pck++)
	delete (*it_pck);
```

Work directly with "raw" pointers can be annoying and is prone to produce memory leaks. This is why many people prefer to use smart pointers. The next code is equivalent except that there is no need to delete the pointers at the end:

```
typedef packet_ptr boost::shared_ptr<Packet>;

vector<packet_ptr> pck_cont;

/* ... push packets in the container ... */
pck_cont.push_back(new ...
pck_cont.push_back(new ...
pck_cont.push_back(new ...
pck_cont.push_back(new ...
pck_cont.push_back(new ...

Send(pck_cont.begin(),pck_cont.end());
```

The previous piece of code will work in the same manner if instead of using a std::vector to store pointers you use std::list or std::deque:

```
list<Packet*> pck_cont;
deque<Packet*> pck_cont;
```

In conclusion, the `Send`, `SocketSend`, `SendRecv` and `SocketSendRecv` functions are independent of the type of pointers and type of container to store them.

The `SendRecv` function returns the reply packets on another container (with enough space to hold the pointers). For example,

```
	string iface = "wlan0";

	IP ip;
	ip.SetSourceIP(GetMyIP(iface));
	ip.SetDestinationIP("192.168.0.1");

	vector<Packet*> pck_cont;

	pck_cont.push_back(new Packet(ip / UDP() / RawLayer("UDPData")));
	pck_cont.push_back(new Packet(ip / TCP() / RawLayer("TCPData")));
	pck_cont.push_back(new Packet(ip / ICMP() / RawLayer("ICMPData")));

	list<Packet*> rcv_cont(pck_cont.size());

	SendRecv(pck_cont.begin(),pck_cont.end(),rcv_cont.begin(),iface);

	list<Packet*>::iterator it_pck;
	for(it_pck = rcv_cont.begin() ; it_pck != rcv_cont.end() ; it_pck++)
                /* Check the NULL pointer! */
		if(*it_pck)
			(*it_pck)->Print();
```

The response packets are stored in another container (`rcv_cont`, could be a std::vector, std::list or std::deque) with the same length as the original (`pck_cont`). There is a one to one correspondence between the two containers. If a particular packet don't produces a answer, a null pointer will be set on the return container.

### What is the advantage of using containers? Is the same to send each packet one by one inside a loop? ###

In the previous examples, yes, is exactly the same because the `num_threads` arguments was not given to the any function.

The advantage of hold the packets in a container and send them all together is that you can use more than one thread to do it. The argument `num_threads` is the number of threads in which the packets to be sent are distributed.

Let's take a simple ICMP traceroute as en example to show how the use of many threads can make a difference. The program takes as an argument the number of threads. The host and the interface should be changed in the source code:

```
#include <iostream>
#include <vector>
#include <string>
#include <crafter.h>

using namespace std;
using namespace Crafter;

int main(int argc, char* argv[]) {
        int nthreads = 0;

        if(argc == 2)
        	nthreads = atoi(argv[1]);

	/* Interface */
	string iface = "wlan0";
	/* Max number of hops */
	int max_ttl = 30;

	/* IP header */
	IP ip;
	ip.SetSourceIP(GetMyIP(iface));
	ip.SetDestinationIP("173.194.42.31");

	/* ICMP header */
	ICMP icmp;
	icmp.SetType(ICMP::EchoRequest);

	/* Create container */
	vector<Packet*> pings;

	for(int ttl = 1 ; ttl <= max_ttl ; ttl++) {
		/* IP data */
		ip.SetIdentification(RNG32());
		ip.SetTTL(ttl);
		/* ICMP data */
		icmp.SetIdentifier(RNG16());
		icmp.SetSequenceNumber(RNG16());

		/* Push the packet into the container */
		pings.push_back(new Packet(ip / icmp));
	}

	/* Hold the responses in new container */
	vector<Packet*> responses(pings.size());

	/* Send all the packets */
	SendRecv(pings.begin(), pings.end(), responses.begin(), iface, 1, 3, nthreads);

	for(int ttl = 0 ; ttl < max_ttl ; ttl++) {
		Packet* pck_ptr = responses[ttl];
		if(pck_ptr) {
			/* Get layers */
			ICMP* icmp_res = pck_ptr->GetLayer<ICMP>();
			IP* ip_res = pck_ptr->GetLayer<IP>();

			if(icmp_res->GetType() == ICMP::EchoReply) {
				cout << "[" << dec << ttl + 1 << "] Final -> " << ip_res->GetSourceIP() << endl;
				break;
			} else
				cout << "[" << dec << ttl + 1 << "] " << ip_res->GetSourceIP() << endl;

		} else
			cout << "[" << dec << ttl + 1 << "] " << "*.*.*.*" << endl;
	}

	return 0;
}
```

The code is quite simple. First we put together 30 (max\_ttl) ICMP echo-request packets with TTL values from 1 to 30 and store them in a container. Then, we create a container to hold the responses and we send the requests with the `SendRecv` function:

```
/*.....*/
	/* Hold the responses in new container */
	vector<Packet*> responses(pings.size());

	/* Send all the packets */
	SendRecv(pings.begin(), pings.end(), responses.begin(), iface, 1, 3, nthreads);
/*.....*/
```

The timeout is 1 second (time after which the function will stop waiting for answers) and the retry parameter is 3 (number of rounds that an unanswered packet is sent). The number of threads `nthreads` is obtained from the command line and by default is 0 (which is equivalent to send all the packets in a loop).

Compile and run the program with different numbers of threads:

```
$ g++ trace.cpp -o trace -lcrafter
$ time sudo ./trace     # default, zero threads
[1] 192.168.0.1
[2] 192.168.1.1
[3] *.*.*.*
[4] 200.51.233.208

.
.
.

[19] 209.85.251.24
[20] 209.85.251.194
[21] Final -> 173.194.42.31

real	0m24.211s
user	0m0.010s
sys	0m0.080s
```

With zero threads traceroute takes 24 seconds... Too much. Let's try with 30 threads (one thread per packet) :

```
$ time sudo ./trace 30
[1] 192.168.0.1
[2] 192.168.1.1
[3] *.*.*.*
[4] 200.51.233.208

.
.
.

[19] 209.85.251.24
[20] 209.85.251.194
[21] Final -> 173.194.42.31

real	0m3.222s
user	0m0.020s
sys	0m0.100s
```

Much better! In this case, the `SendRecv` function performs three rounds with a 3-second timeout and the waiting time is distributed among many threads resulting is a more efficient use of CPU.

# Working with pcap files #

Libcrafter provides an interface to dump a packet container into a pcap file, and construct a container of packets from a pcap file. The functions that perform these tasks are:

  * `void DumpPcap(FowardIter begin, FowardIter end, const std::string& filename)`
  * `void ReadPcap(Seq* pck_container, const string& filename, const string& filter = "")`

For example, dumping a packet container on the "container.pcap" file can be done with the next piece of code:

```
string iface = "wlan0";

IP ip;
ip.SetSourceIP(GetMyIP(iface));
ip.SetDestinationIP("1.2.3.4");
	
vector<Packet*> pck_cont;

pck_cont.push_back(new Packet(ip / UDP() / RawLayer("UDPData")));
pck_cont.push_back(new Packet(ip / TCP() / RawLayer("TCPData")));
pck_cont.push_back(new Packet(ip / ICMP() / RawLayer("ICMPData")));

DumpPcap(pck_cont.begin(),pck_cont.end(),"container.pcap");
```

The reverse can be done with the next code:

```
vector<Packet*> pck_cont;

ReadPcap(&pck_cont,"container.pcap");

vector<Packet*>::iterator it_pck;
for(it_pck = rcv_cont.begin() ; it_pck != rcv_cont.end() ; it_pck++)
    (*it_pck)->Print();
```

You can also specify a filter to construct the container with the packets that you want. For example,

```
ReadPcap(&pck_cont,"container.pcap","tcp and port 80");
```