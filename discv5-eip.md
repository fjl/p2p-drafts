## Abstract

A new UDP-based peer discovery protocol is proposed that is built upon a Kademlia structure similar to that of the existing RLPx v4 protocol. In addition to building a strong network topology and being able to search for a specific node address, nodes can also advertise themselves associated with arbitrary string identifiers or so-called "topics". Nodes participating in the topic discovery protocol act as advertisement media, meaning that they accept topic registrations from advertising nodes and later return them to nodes searching for the same topic.

## Motivation

Although DevP2P can negotiate protocol capabilities, actually finding suitable nodes is hard if one is not looking for someone running the ETH protocol on the main net. Both alternative networks (testnets, private nets) and alternative protocols (like LES) are hard to find by just randomly wandering around the peer discovery network. Topics can be used to signal certain protocol capabilities. They do not necessarily need to have a one-to-one mapping to protocols, they can also identify specific roles of a protocol. Depending on the protocol hierarchy, a node can advertise itself under multiple topics or no topics at all.

## Specification

### Kademlia network lookup

Similarly to the existing peer discovery, the network is constructed with a Kademlia topology where the lookup address is SHA3(nodePubKey). One notable difference from the old protocol is the lookup format: instead of looking for a certain nodePubKey, lookup address is directly specified. This makes it possible to do random address lookups in certain subsets of the address range.

### Registration Mechanism

Let us assume that node A advertises itself under topic T. It selects node C as advertisement medium and wants to place an ad (including its enode and IP address/port number), so that when node B (who is looking for topic T) asks C, C can return the registration entry of A to B.

C has a fixed-length FIFO registration storage for each topic. For each topic, the registration frequency is limited, which ensures a certain average lifetime for registrations. Limiting registration frequency on the receiving side is achieved by introducing a wait period into the registration mechanism: A first receives a signed "ticket" from C. This ticket contains a serial number and the wait period, after which A can send a registration request to C. The request includes the ticket so that C does not need to remember its issued tickets, just the serial number of the latest ticket accepted from A (after which it will not accept any tickets issued earlier).

The wait period belonging to topic T is increased exponentially every time C accepts a registration for that topic. Between accepted registrations, it continually decreases exponentially with a fixed time constant until it reaches a minimum value. This mechanism acts as a control loop, limiting average registration rate per topic at a desired value (targetRegFrequency = targetRegLifetime / FIFOlen, where targetRegLifetime is currently 10 minutes).

There is also a global limit on stored registrations, and when this limit is reached, the least recently accessed (either created or queried) registration is thrown away.

### Proposed registration and query messages

Getting a ticket:

    A.requestTicket(topic) -> C
    C.ticket(sn, topic, localTime, waitPeriod) -> A

Registering after waitPeriod has elapsed:

    A.topicRegister(C.ticket(sn, topic, localTime, waitPeriod)) -> C
    (the entire signed ticket message is returned as a parameter)

Looking for registrations:

    B.topicQuery(topic) -> C
    C.topicNodes([]nodeID{..., A.id, ...}) -> B

### Ad Placement And Topic Radius Detection

When the number of nodes advertising a topic (topic size) is at least a certain percentage of the whole topic discovery network (rough estimate: at least 1%), the "birthday paradox" makes it sufficient to select random nodes to place ads and also look for ads at randomly selected nodes. A topic size that is 1% of the network size ensures that if every advertiser has 10 active ads, searchers will find a relevant registration entry per 10 lookups on average.

In case of a very high network size/topic size ratio, it helps to have a convention for selecting a subset of nodes as potential advertisement media for a given topic. This subset is defined as the nodes whose Kademlia address is close to SHA3(topic), meaning that the binary XOR of the address and the topic hash interpreted as a fixed point number is smaller than a given "topic radius" (a radius of 1 means the entire network, in which case advertisements are distributed uniformly).

Example:

- nodes in the topic discovery network: 10000
- number of advertisers of topic T: 100
- registration frequency: 3 per minute
- average registration lifetime: 10 minutes
- average number of registrations of topic T at any moment: 3 * 10 * 100 = 3000
- expected number of registrations of T found at a randomly selected node (topic density) assuming a topic radius of 1: 0.3

In order to make topic discovery work for smaller topics, we need a mechanism to find a suitable topic radius. The desired radius is specified as the largest radius where a randomly selected node will return a relevant registration with a sufficiently high probability (topic density is sufficiently high, in other words). To find this radius, both advertisers and searchers should initially try selecting nodes with an assumed topic radius of 1 and collect statistical data about the density of registrations at the selected nodes. If the topic density in the currently assumed topic radius is under the target level (0.3 in our example), the radius is decreased.

It is possible that there are only a few or no active registrations for the topic at all and the target density is never reached by decreasing the radius. There is no point in decreasing the targeted node subset under the size of approximately 100 nodes since in this case even a single advertiser can easily be found (the same reasoning applies about the birthday paradox). Approximating the number of nodes in a given address subset is possible by collecting statistical data about the average distance between a randomly selected address and the address of the closest actual node found. If the approximated number of nodes in our topic radius is under 100, we increase the radius.

## Design rationale

Topic discovery is not meant to be the only mechanism used for selecting peers. A persistent database of useful peers is also recommended, where the meaning of "useful" is protocol-specific. Like any DHT algorithm, topic discovery is based on the law of large numbers. It is easy to spread junk in it at the cost of wasting some resources. Creating a more trusted sub-network of peers over time prevents any such attack from disrupting operation, removing incentives to waste resources on trying to do so. A protocol-level recommendation-based trust system can be useful, the protocol may even have its own network topology.
The reason topic discovery is proposed in addition to application-specific networks is to solve bootstrapping issues and improve downward scalability of subnetworks. Scalable networks that have small subnetworks (and maybe even create new subnetworks automatically) cannot afford to require a trusted bootnode for each of those subnets. Without a trusted bootnode, small p2p networks are very hard to bootstrap and also more vulnerable to attacks that could isolate nodes, especially the new ones which don't know any trusted peers. Even though a global registry can also be spammed in order to make it harder to find useful and honest peers, it makes complete isolation a lot harder because in order to prevent the nodes of a small subnet from finding each other, the entire topic discovery network would have to be overpowered.

### Security considerations

#### Spamming with useless registrations

Our model is based on the following assumptions:

- Anyone can place their own advertisements under any topics and the rate of placing registrations is not limited globally. The number of active registrations at any time is roughly proportional to the resources (network bandwidth, mostly) spent on advertising.
- Honest actors whose purpose is to connect to other honest actors will spend an adequate amount of efforts on registering and searching for registrations, depending on the rate of newly established connections they are targeting. If the given topic is used only by honest actors, a few registrations per minute will be satisfactory, regardless of the size of the subnetwork.
- Dishonest actors (attackers) may want to place an excessive amount of registrations just to disrupt the discovery service. This will reduce the effectiveness of honest registration efforts by increasing the topic radius and/or the waiting times. If the attacker(s) can place a comparable amount or more registrations than all honest actors combined then the rate of new (useful) connections established throughout the network will be reduced.

This adverse effect can be countered by honest actors increasing their registration and search efforts. Fortunately, the rate of established connections between them will increase proportionally both with increased honest registration and search efforts. If both are increased in response to an attack, the required factor of increased efforts from honest actors is proportional to the square root of the attacker's efforts.

#### Detecting a useless registration attack

In the case of a symmetrical protocol (where nodes are both searching and advertising under the same topic) it is easy to detect when most of the queried registrations turn out to be useless and increase both registration and query frequency. It is a bit harder but still possible with asymmetrical (client-server) protocols, where only clients can easily detect useless registrations, while advertisers (servers) do not have a direct way of detecting when they should increase their advertising efforts. One possible solution is for servers to also act as clients just to test the server capabilities of some of the other advertisers (especially those with a lot of active ads). It is also possible to implement a feedback system between trusted clients and servers.

#### Amplifying network traffic by returning fake registrations

An attacker might wish to direct discovery traffic to a chosen address. This is prevented by not returning endpoint details in the `topicNodes` message.

#### Not registering/returning valid registrations

Although the limited registration frequency ensures that the resource requirements of acting as a proper advertisement medium are sufficiently low, such selfish behavior is possible, especially if some client implementations choose the easy way and not implement it at all. This is not a serious problem as long as the majority of nodes are acting properly, which will hopefully be the case. Advertisers can easily detect if their registrations are not returned so it is probably possible to implement a mechanism to weed out selfish nodes if necessary, but the design of such a mechanism is outside the scope of this document.

