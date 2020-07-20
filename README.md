# The (Democracy) Secure Ad-hoc Network - (D)SAN
## A Secure Implementation of B.A.T.M.A.N., forked from secure-ad-hoc-network by 'loosky'

### Introduction
The Democracy Secure Ad-hoc Network is a secure implementation of the pro-active ad-hoc routing protocol [B.A.T.M.A.N. Daemon](https://github.com/open-mesh-mirror/batmand).

It builds off the work of [Espen Graarud's secure-ad-hoc-network](https://github.com/loosky/secure-ad-hoc-network), which provided the ground-work for interacting with the B.A.T.M.A.N. Daemon code, as well as the secure transmission of data between network nodes. This implementation is better described as a *fork* of Graarud's work as it aims to keep the same functional philosophy with the addition of bug-fixes that adapt it to modern Linux systems and new functions and mechanisms that reflect this repo's potential use: **aerial drone networking.**

### Definition of Network Nodes
The (D)SAN uses the following hierarchy for the sake of distributing *Proxy Certificates* to network nodes:

* **Service Proxy** - The Master Node of the Network. This node serves Proxy Certificates for other nodes in the network. In this scheme, **only one** SP is allowed in the network at a time. If a SP goes missing in the network, the remaining nodes within the network will consult with each other to decide which node should become the new SP. Only the SP can authenticate nodes that are new to the network. If the network intends to always look for new nodes to add, then an SP is always necessary in the network. This implementation assumes that an SP is always wanted.
* **Authenticated** - Normal nodes within the Network. These nodes cannot add new unauthenticated nodes within the network, but they can re-add already authenticated network nodes that have gone missing at some point.

## Flow of Operation
*Ack: Some of the operation of this program comes from Graarud's secure-ad-hoc-network. His work has been extremely helpful in creating this implementation and I would like acknowledge his breakthroughs in securing ad-hoc networks.*

### Initialization
First, the nodes of the network must be initialized from their respective local terminals.

The command to initialize a SP within the network is:
> ./batmand --role sp -d 4 wlan0

#### ...where the network interface is assumed to be 'wlan0.'

The command to initialize an authenticated node within the network is:
> ./batmand --role authenticated -d 4 wlan0

#### ...where the network interface is assumed to be 'wlan0.'
----------------------------------------------
#### Side-note about IP Configuration: IP Address Configuration is actually handled by BATMAN, rather than this software that is built on top of it. To configure the network interface you plan to use as an ad-hoc antenna, consult these instructions from the BATMAN Team:
### Getting started with the batman daemon

Make sure you have no firewall running that is blocking UDP
port 4305 (originator messages), port 4306 (gateway traffic).
Port 4307 has to be open for incoming UDP traffic if you run the
B.A.T.M.A.N. visualization server.

First the network interfaces supposed to participate
in the batman mesh must be configured properly. You either run it on top
of any "normal" network interface (WiFi, Ethernet, etc) or on an alias
interface. In normal scenarios the alias interface is not needed unless
you want to test / verify / benchmark B.A.T.M.A.N.

Alias interface example: Assuming you have an already configured
interface eth1 with the IP address of 104.1.12.123/8 and want to run
batman in parallel on the same physical interface but with a
105.1.12.123/8 IP/netmask.

> ifconfig eth1:bat 105.1.12.123 netmask 255.0.0.0 broadcast 105.255.255.255
> batmand -d 3 eth1:bat

This will configure an alias interface on top of eth1 named eth1:bat and start
the batman daemon with debug level 3 on that alias interface. As soon as
another running batmand (with the same netmask and broadcast address) is
connected to that link (or within the range of the wireless link)
both batman daemons should see each other and indicate this in the debug output.

The daemon started with debug level 3 can be terminated with ctrl-c.
If no debug level is given at startup, using

> batmand eth1:bat

the daemon will immediately fork to the background (as is the usual behavior
of a daemon). However you can always connect to the main daemon (running
in background) by launching a client-batmand process with the
-c and -d <number> option, where the number represents the desired
debug-level. The following command will connect to a running batmand
process providing debug-level 1 informations.

> batmand -c -d 1 # shows a list of other nodes in the mesh

> batmand -c -d 2 # shows a list of nodes offering internet GW access

> route -n # shows your current routing table as modified by batmand

For a full list of supported debug-levels and other startup options see

> batmand -h # providing a brief summary of options and

> batmand -H # for a more detailed list of options

Use ctrl-c to terminate a process running in foreground and

> killall batmand

to terminate the main batmand daemon running in background.

If you want to use one of the batman-internet gateways showed with
debug-level 2 launch the main batmand using:

> batmand -r 3 eth1:bat # to automatically select a reasonable GW

> batmand -r 3 -p <ip-of-batmand-gw-node> eth1:bat # to set a preferred GW

----------------------------------------------------------------------------
### Building the Network: Adding new nodes in the network using an SP
When the SP is initialized, an origin proxy certificate, *PC0*, is generated. This certificate is self-signed and requires no other proxies to create. This certificate will be used to sign other Proxy Certificates in the network. Because of this, if new nodes are assumed to join the network in the midst of operation, an SP node is always necessary to ensure their secure addition to the system.

After initializing at least one SP and one AUTHENTICATED node, the network can now be constructed. The AUTHENTICATED node will initialize as a node without a Proxy Certificate, and will search for an SP node so that it may join the network. Once the SP Node and newly created AUTHENTICATED node become direct network neighbors, the two engage in an authentication process that results in the creation of a *signed proxy certificate* for the AUTHENTICATED node to use. This certificate is referred to as a *PC1*, as it originates from a *PC0* certificate that is held by the SP. **Only PC0 certificates are able to self-sign other certificates for other nodes in the network to use. ALL authenticated nodes in the network must have proxy certificates signed by the same Service Proxy.**

### Message Sending between Nodes
B.A.T.M.A.N. is a *pro-active network*, meaning that *whether data needs to be sent or not, messages are still sent between network nodes to ensure they are still connected.* Taking advantage of this, the (D)SAC uses packet messages between nodes to ensure that only authenticated nodes are allowed in the network, which is achieved by proactively providing *keystream* messages that validate the authentication relationship between nodes of all roles.

Building off this, the (D)SAC adds message functions that ensure that *an SP is always present in the network.* Should, through these messages, it be discovered that an SP Node is *missing* from this network, then these same established messaging protocols are used to both decide *where* a new SP Node should be, as well as to *reboot* the network so to use the proxy certificates of the newly-created SP node.

### When is an SP not needed?
In some situations, the full implementation of the (D)SAC may not be necessary. This includes situations where *you already know the number of nodes that will be in your network and you can authenticate them initially.* An example of this particular scheme is if you can authenticate a swarm of drones before they take off, and no new drones are expected to join the network mid-air. This means that only drones within the swarm can re-join the network if lost, ultimately creating a *walled garden* ad-hoc network.

However, in situations where...
* The consistent performance of a node is in question (i.e. the node has the possibility of powering off)
* New nodes are expected to join mid-operation.

...an SP node should be kept in the network.

### What happens when an SP is potentially missing from the network?
During normal AUTHENTICATED node operation, after engaging with other nodes to ensure authentication status is intact, the node will check its direct neighbor list to see if an SP node resides in the network as a neighbor. Should the node detect that an SP node is not available as a direct neighbor, the node will flag this as a potential issue to investigate.

Before continuing further, the network engages in an **election process** (hence the name) to determine which remaining node within the network would make the best SP Node candidate. The information used to determine the best SP Node candidate is the *timestamp of when the node discovered that an SP was missing*, hence the new SP Node is decided on a First Come, First Serve basis. This mechanism is done to prevent multiple SP nodes from joining the network, as a requirement of this ad-hoc network configuration is that *only one SP node is allowed at a time.*

Before making assumptions that an SP node must be missing, there are possible explanations to this problem that do not implicate that an issue exists:

* An SP node resides in the network, but just isn't a neighbor to the node.
* The node has no neighbors at all. (This issue is immediately detected and no further action is taken until a new neighbor is found.)

To ensure that the missing SP node is not just due to the fact that its within the network but not a neighbor, the alerted node will begin a search for an SP node in the network by making use of a newly-created feature: **Neighbor Nudge**. Neighbor Nudge is a lightweight way to send small packets of information between connected nodes in the network that do not contain compromising information about the network, such as authentication information.

Using Neighbor Nudge, the search for an SP node within the network is conducted by flooding the network with messages containing requests for each node to search their neighbors for an SP node. One of two outcomes are possible from this process:

* An SP node is found in the neighbor list of an authenticated node in the network. The location of this node is sent back to the originator of the request.

* After a specified timeout period, it is assumed that an SP node does not exist in the network, and a reboot process in initiated for a remaining node in the network to take the SP nodes place.

Should the former occur, then the network infrastructure is kept as is, with the found SP node remaining as the Master Node of the network. However, should the latter occur, then a newly-developed mechanism to reboot the network to work with a newly designated SP Node will take place.

### Rebooting the Network

When the SP Node is determined to *not* be part of the network anymore, and an SP Candidate has been elected, the SP Candidate node will initiate a soft reboot of the network so that each node in the network will be authenticated by a newly created PC0 that will reside with the SP Candidate node. During this process, the SP Candidate will convert its role from AUTHENTICATED to SP, and the rest of the nodes in the network will be, if not already, be set to AUTHENTICATED. This process will require the newly-set AUTHENTICATED node to register with the newly-designated SP Node for Proxy Certificates, as their previous ones only held valid for the previous SP Node.

After a node is rebooted, a cooldown period of a specified time (currently at 15 seconds) is engaged to prevent repeated reboots from one command. After this cooldown period, each node in the network is set to engage in normal activity.
