# Introduction #

LibCrafter is a C++ library developed for the creation, manipulation and decoding of network packets. There are a few concepts that you should be familiar with before trying to use libcrafter.

## Using layers ##

A **network packet** can be described as **layers** that you stack one upon the other. The general layout of a layer is shown in the next figure:

![http://figures.libcrafter.googlecode.com/git/layerout.png](http://figures.libcrafter.googlecode.com/git/layerout.png)

There is a _header_ (green) of fixed size which contains different fields. Fields of each layer have useful default values that you can overload. At the end of the header, there is a _payload_ (blue), which is a chunk of data of variable and arbitrary size.

The `Crafter::Layer` class is an abstract class designed to manage this data structure, which is the base of all protocols implemented in libcrafter. All the classes derived from the `Layer` class have a set of common methods that I will list briefly:

  * `string GetName() const`: Get the name of the protocol as a string that is represented by the layer (like "_UDP_", "_IP_", "_Ethernet_", etc)

  * `short_word GetID() const`: Get the protocol ID of the layer. For example, 0x06 for TCP, 0x01 for ICMP and so on.

  * `size_t GetSize() const`: Get the total size in bytes of the layer, the header size plus the payload size.

  * `size_t GetHeaderSize() const`: Get the _header_ size in bytes of the layer. For a specific protocol, this function always return the same number (20 bytes for IP, 8 bytes for UDP, etc).

  * `size_t GetPayloadSize() const`: Get the _payload_ size in bytes.

  * `void HexDump(ostream& str = cout) const`: Print the bytes on a layer in hexadecimal format, like:
```
    45000027 00004000 4001A5EB C0A80067  E..'..@.@......g 00000000
    4A7D895E 0800E85C 10F10000 48656C6C  J}.^...\....Hell 00000010
```
  * `void Print(ostream& str = cout) const`: Print the values of each field and the payload of a layer in human-readable form, like:
```
   < ICMP (8 bytes) :: Type = 8 , Code = 0 , CheckSum = 0xe85c , Identifier = 0x10f1 , SequenceNumber = 0x0 , >
```
  * `void RawString(ostream& str = cout) const`: Print the bytes of a layer in a C-style hexadecimal string, like:
```
   \x45\x0\x0\x27\x0\x0\x40\x0\x40\x1\xa5\xeb\xc0\xa8\x0\x67\x4a\x7d
```
  * `size_t PutData(const byte* data)`: This method construct a layer and set all its fields from the raw data provided as an argument. The return value is the number of bytes used to construct the layer (i.e. the header size).

  * `size_t GetRawData(byte* buffer) const`: This method puts the data of the layer into a buffer with enough space to hold all the bytes. A common way to use this method is:
```
   SomeProtocol* layer;
   /* ... some code ... */
   byte* buffer = new byte[layer->GetSize()]
   layer->GetRawData(buffer);
   /* ...more code... */
   delete [] buffer
```
  * Methods to manipulate the payload:
    * `void SetPayload (const byte *data, int ndata)` ; `void SetPayload (const char *data)` : Set the payload of a layer. .
    * `void AddPayload (const byte *data, int ndata)` ; `void AddPayload (const char *data)` : Concatenate the data to the to the existing payload (if there isn't a payload, creates one).
    * `size_t GetPayload(byte* dst) const`: This method puts the data of the payload into a buffer (`dst`) with enough space to hold all the bytes.
    * `const Payload& GetPayload() const`: This function returns a constant reference to a `Payload` object. A common way to use this method is to get a STL vector of bytes with the payload data. For example,
```
   SomeProtocol* layer;
   /* ... some code that set the layer and payload ... */
   std::vector<byte> payload_data = layer->GetPayload().GetContainer;
   /* Access the data on the payload */
   cout << payload_data[0] << " ; " <<  payload_data[1] << endl;
```
    * `std::string GetStringPayload() const`: This method returns a STL string with the payload on it. Useful when the payload of a layer is an ASCII string.

The available protocols in libcrafter, which are classes derived from the base class `Layer`, are:

  * Ethernet
  * SSL
  * ARP
  * ICMP and ICMP extensions
  * IP and IP options
  * IPv6
  * TCP and TCP options
  * UDP
  * DNS
  * DHCP
  * RawLayer (a generic layer with no fields/header and a payload)

Each protocol has its own specific set of methods to set the fields associated with the layer. For example, an IP layer has some methods for setting the source and destination IP address, an ICMP layer has methods for setting the type and code of the message, and so on. Later I will show most of the common methods of each protocol (most functions names are highly descriptive).

For example, the next code will access and print general information of some specific protocol with each of its fields and default values:

```
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

static void PrintInfo(const Layer& layer) {
	cout << "[@] -- Print general info: " << endl;
	cout << layer.GetName() << "(0x" << hex << layer.GetID() << ")" << " = " << dec << layer.GetSize() << " bytes. " << endl;
	cout << "[@] -- Print fields and default values: " << endl;
	layer.Print();
	cout << endl;
}

int main() {

	PrintInfo(Ethernet());
	PrintInfo(IP());
	PrintInfo(ARP());
	PrintInfo(TCP());
	PrintInfo(UDP());
	PrintInfo(ICMP());

	return 0;
}
```

The output on the screen should be:

```
$ g++ info.cpp -o info -lcrafter
$ ./info
[@] -- Print general info: 
Ethernet(0xfff2) = 14 bytes. 
[@] -- Print fields and default values: 
< Ethernet (14 bytes) :: DestinationMAC = ff:ff:ff:ff:ff:ff , SourceMAC = 00:00:00:00:00:00 , Type = 0x800 , >

[@] -- Print general info: 
IP(0x800) = 20 bytes. 
[@] -- Print fields and default values: 
< IP (20 bytes) :: Version = 4 , HeaderLength = 5 , DiffServicesCP = 0 , ExpCongestionNot = 0 , TotalLength = 0 , Identification = 0x0 , Flags = 2 , FragmentOffset = 0 , TTL = 64 , Protocol = 0x6 , CheckSum = 0x0 , SourceIP = 0.0.0.0 , DestinationIP = 0.0.0.0 , >

[@] -- Print general info: 
ARP(0x806) = 28 bytes. 
[@] -- Print fields and default values: 
< ARP (28 bytes) :: HardwareType = 0x1 , ProtocolType = 0x800 , HardwareLength = 6 , ProtocolLength = 4 , Operation = 1 , SenderMAC = 00:00:00:00:00:00 , SenderIP = 127.0.0.1 , TargetMAC = 00:00:00:00:00:00 , TargetIP = 127.0.0.1 , >

[@] -- Print general info: 
TCP(0x6) = 20 bytes. 
[@] -- Print fields and default values: 
< TCP (20 bytes) :: SrcPort = 0 , DstPort = 80 , SeqNumber = 0 , AckNumber = 0 , DataOffset = 5 , Reserved = 0 , Flags = ( ) , WindowsSize = 5840 , CheckSum = 0x0 , UrgPointer = 0 , >

[@] -- Print general info: 
UDP(0x11) = 8 bytes. 
[@] -- Print fields and default values: 
< UDP (8 bytes) :: SrcPort = 0 , DstPort = 53 , Length = 0 , CheckSum = 0x0 , >

[@] -- Print general info: 
ICMP(0x1) = 8 bytes. 
[@] -- Print fields and default values: 
< ICMP (8 bytes) :: Type = 8 , Code = 0 , CheckSum = 0x0 , RestOfHeader = 0 , >
```

## Using packets ##

A `Packet` class can be viewed as a container of layers where each one is directly related to its neighboring layers. To be more precise, a packet is a container of pointers to layers objects to use properly the polymorphism of the `Layer` abstract class. You can push and pop layers from a packet in various ways. The most intuitive way is using the `/` operator and access each pushed layer with the `[]` operator. Let's take a look to the next example:

```
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

static void PrintLayerInfo(const Layer& layer) {
	cout << "[@] -- Print general info: " << endl;
	cout << layer.GetName() << "(0x" << hex << layer.GetID() << ")" << " = " << dec << layer.GetSize() << " bytes. " << endl;
	cout << "[@] -- Print fields and values: " << endl;
	layer.Print();
	cout << endl;
}

static void PrintInfo(const Packet& packet) {
	for(size_t i = 0 ; i < packet.GetLayerCount() ; i++)
		/* packet[i] gives a pointer to the layer on position "i" on the stack */
		PrintLayerInfo( (*packet[i]) );
}

int main() {

	/* Define some layers */
	Ethernet ether;
	IP ip;

	/* Create a packet */
	Packet pck = ether / ip;

	/* Create more layers */
	UDP udp;
	RawLayer raw("UDPData");

	/* Push the UDP and the data */
	pck /= udp / raw;

	PrintInfo(pck);

	return 0;
}
```

First, we instantiate some layer objects (Ethernet and IP) and create a packet to hold both layers. Then we create two more layer objects (UDP and a RawLayer) and push them into the already created packet. Finally, we use the `PrintInfo` function to access each layer on the packet and print some information of them (using the PrintLayerInfo function). The output on the screen should be:

```
$ g++ packet.cpp -o packet -lcrafter
$ ./packet
[@] -- Print general info: 
Ethernet(0xfff2) = 14 bytes. 
[@] -- Print fields and values: 
< Ethernet (14 bytes) :: DestinationMAC = ff:ff:ff:ff:ff:ff , SourceMAC = 00:00:00:00:00:00 , Type = 0x800 , >

[@] -- Print general info: 
IP(0x800) = 20 bytes. 
[@] -- Print fields and values: 
< IP (20 bytes) :: Version = 4 , HeaderLength = 5 , DiffServicesCP = 0 , ExpCongestionNot = 0 , TotalLength = 0 , Identification = 0x0 , Flags = 2 , FragmentOffset = 0 , TTL = 64 , Protocol = 0x6 , CheckSum = 0x0 , SourceIP = 0.0.0.0 , DestinationIP = 0.0.0.0 , >

[@] -- Print general info: 
UDP(0x11) = 8 bytes. 
[@] -- Print fields and values: 
< UDP (8 bytes) :: SrcPort = 0 , DstPort = 53 , Length = 0 , CheckSum = 0x0 , >

[@] -- Print general info: 
RawLayer(0xfff1) = 7 bytes. 
[@] -- Print fields and values: 
< RawLayer (7 bytes) :: Payload = UDPData>
```

If you feel more comfortable using iterators, the `PrintInfo` function in the last example could be replaced by:

```
static void PrintInfo(const Packet& packet) {
	LayerStack::const_iterator it = packet.begin();
	for(; it != packet.end() ; it++)
		/* (*it) gives a pointer to the layer */
		PrintLayerInfo( *(*it) );
}
```

`LayerStack` is a typedef of the STL container I use to hold the pointers of the layers inside a packet. Currently is `vector<Layer*>` but you should use `LayeStack` instead just in case I change my mind someday.

The `Print` method of the `Packet` class also prints most of that information (the last code is just to show you how to access a layer on a packet):
```
pck.Print();
```
will output,
```
< Ethernet (14 bytes) :: DestinationMAC = ff:ff:ff:ff:ff:ff , SourceMAC = 00:00:00:00:00:00 , Type = 0x800 , >
< IP (20 bytes) :: Version = 4 , HeaderLength = 5 , DiffServicesCP = 0 , ExpCongestionNot = 0 , TotalLength = 0 , Identification = 0x0 , Flags = 2 , FragmentOffset = 0 , TTL = 64 , Protocol = 0x6 , CheckSum = 0x0 , SourceIP = 0.0.0.0 , DestinationIP = 0.0.0.0 , >
< UDP (8 bytes) :: SrcPort = 0 , DstPort = 53 , Length = 0 , CheckSum = 0x0 , >
< RawLayer (7 bytes) :: Payload = UDPData>
```

## Packet manipulation ##

Before listing the methods of the `Packet` class there is a very obvious and important remark about the way the `Packet` class deals with layers: **A packet have its own copy of each layer on the stack**

For example,

```
IP ip;
UDP udp;
udp.SetDstPort(63);
udp.SetSrcPort(1234);

Packet pck = ip / udp;
pck.print();
```

The `pck` object contains an IP layer and a UDP layer with a source port equal to 63 and a destination port equal to 1234. If "later" on the program, the `udp` layer used to construct the packet is changed, that change wouldn't be reflected on the `pck` object:
```
/*...continuation...*/
udp.SetDstPort(564);
udp.SetSrcPort(12341);

/* The packet still have a source port of 63 and a destination port of 1234 */
pck.print();
```

If you want to modify the fields of a layer inside a packet, you should do it with special methods to access layers within the packet (that will be presented later in this section).

### Writing packets on the network ###

  * `int Send(const std::string& iface = "")`: Put a packet into the wire. The `iface` argument is optional if you are crafting a layer 3 packet (IP layer without a link layer). If your packet contains an `Ethernet` layer you should specify the interface to send it. On success, these call return  the  number  of  characters  sent. On error, -1 is returned and you should check errno to see what happened.
  * `Packet* SendRecv(const string& iface = "",double timeout = 1, int retry = 3, const string& user_filter = " ")`: The function returns a pointer to a response packet allocated on the heap. It's user's responsibility to delete it after being used. If no matching answer comes from the net, the function returns a null pointer. It is also user's responsibility to check the return value of this function. The arguments are:
    * `iface` : Network interface. `"wlan0"`, `"eth0"`, etc.
    * `timeout` : Can be assigned a time in seconds after which the function will stop waiting for answers.
    * `retry` : Fixes the maximum number of times a packet can be sent. If the packet that is unanswered after the first round will be sent again in another round, and again and again until it is answered or the number of sending reaches the value of retry. The timeout parameter is used every round.
    * `user_filter` : By default, the library will try to do the best for matching a packet with an answer (using harcoded filter expression for each protocol). Of course, programmers are human and can make mistakes. If the package returned by the function does not satisfy you, you can set the filter (in tcpdump syntax) to match an answer from the net.
  * `int SocketSend(int sd)`: Like the Send function, but the packet is sent through your (already open) socket. The method just writes the crafted data into the socket, so is your responsibility to set the socket options according to your needs. On success, these call return  the  number  of  characters  sent. On error, -1 is returned and you should check errno to see what happened.
  * `Packet* SocketSendRecv(int sd, const string& iface = "",double timeout = 1, int retry = 3, const string& user_filter = " ")`: Like SendRecv but the packet is sent through your (already open) socket. The method will listen on the specified interface (`iface`) the response packet.

### Print and access packet data ###

  * `size_t GetData(byte* raw_ptr)`: Put raw data on array and returns the number of bytes copied.
  * `const byte* GetRawPtr()`: Get a pointer to the raw buffer inside the packet (which holds the crafted data).
  * `size_t GetSize() const`: Get size of the packet in bytes.
  * `void Print(ostream& str = cout) const`: Print the values of each field of each layer on the packet in human-readable form .
  * `void HexDump(ostream& str = cout) const`: Dumps the bytes on a layer in hexadecimal format.
  * `void RawString(ostream& str = cout) const`: Dumps the bytes of a layer in a C-style hexadecimal string.

### Layer access and manipulation ###

  * `void PushLayer(const Layer& layer)` : You may push a layer on the top of the packet calling the PushLayer method. This is much more efficient than the "/" operator. For example, the code
```
  packet= layer_bottom / layer_middle / layer_top; 
```
> could be replaced by
```
  packet.PushLayer(layer_bottom); 
  packet.PushLayer(layer_middle); 
  packet.PushLayer(layer_top);
```
  * `void PopLayer()`: This pop the layer on top of the packet.
  * `template<class Protocol> Protocol* GetLayer(size_t n) const`: The next example shows how to use this method:
```
/* Create a packet */
Packet pck(Ethernet() / IP() / UDP() / RawLayer("Data"));
   
/* We know that the layer number "2" is an UDP layer (the layer count start from zero). So, is safe to do: */
UDP* udp_layer = pck.GetLayer<UDP>(2);
/* udp is a pointer to the UDP layer on the "pck" packet */
udp_layer->SetDstPort(115); /* Change the destination port */

/* That change is done directly on the layer inside the "pck" object, so it will be reflected on futher use of "pck" */
pck.Send();
```
> The line of code:
```
UDP* udp_layer = pck.GetLayer<UDP>(2);
```
> is equivalent to do,
```
UDP* udp_layer = dynamic_cast<UDP*>(pck[2]);
```
  * `template<class Protocol> Protocol* GetLayer() const`: Return a pointer to the first occurrence of the respective layer (Protocol class) on the packet. If there isn't a Protocol layer, the function will return a null pointer (is the user's responsibility to check the returned value). Using as an example the last piece of code,
```
/* Create a packet */
Packet pck(Ethernet() / IP() / UDP() / RawLayer("Data"));
   
UDP* udp_layer = pck.GetLayer<UDP>();

if(udp_layer)
  udp_layer->SetDstPort(115); 
else
  cout << "No UDP layer " << endl;
```
> As you may guess, using `GetLayer<UDP>(2)` is more efficient than `GetLayer<UDP>()`. But sometimes you can't rely on a fixed position of a layer :-(.
  * `template<class Protocol> Protocol* GetLayer(const Protocol* from) const`: Like the last function but get the next layer of a specific type from a start point. For example, if a packet contains two `UDP` layers (I don't know why, is just an example):
```
/* First occurrence in the stack of an UDP layer */
UDP* udp_first = packet.GetLayer<UDP>();
if(udp_first)
  /* ...do some stuff... */

/* Next UDP layer on packet's stack */
UDP* udp_second = packet.GetLayer<UDP>(udp_first);
if(udp_second)
  /* ...do some stuff... */

```
  * `size_t GetLayerCount() const`: Get the numbers of layers on the stack.
  * Iterators:
    * `LayerStack::iterator begin()`
    * `LayerStack::iterator end()`
    * `LayerStack::const_iterator begin() const`
    * `LayerStack::const_iterator end() const`
    * `LayerStack::reverse_iterator rbegin()`
    * `LayerStack::reverse_iterator rend()`
    * `LayerStack::const_reverse_iterator rbegin() const`
    * `LayerStack::const_reverse_iterator rend() const`