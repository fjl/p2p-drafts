### Abstract

The RLPx protocol relies on a Distributed Peer Table ('DPT') to relay endpoint
information. Nodes register their public key and endpoint in the DPT using a Kademlia-like
protocol (the 'discovery protocol').

Each node in the Ethereum network has a set of tags called "topics" by which other nodes
may choose to associate with them. They may indicate capability, responsibility for
certain information or functionality or any other attribute by which the node may wish to
belong to a connected subnetwork of the devp2p network. In this document, an
infrastructure is outlined by which nodes interested in a certain topic may discover other
nodes providing that topic.

### Specification
#### Topics

On the lowest level, a topic is denoted by a byte array.

On a higher level, two possible hierarchical topic structures are defined: one in which
nodes covered by a topic and all its subtopics are searched and another in which nodes a
list that has the parent topic list as its prefix. covered by a topic and all its
supertopics are searched.

The two higher-level hierarchies are handled as follows: In the first case, when nodes
covered by subtopics need to be discoverable, nodes must be tagged by their topic and all
their supertopics (e.g a node covered by `[ 0x01, 0x02, 0x03 ]` is also covered by
`[ 0x01, 0x02 ]` and `[ 0x01 ]`, so that a search for `[ 0x01, 0x02 ]` will find it).

In the second case, when nodes covered by supertopics need to be discoverable, the node
doing the discovery also searches for all the supertopics. Apart from this, the directory
is topic structure agnostic.

#### Topic Association Storage

Each node participating in the DPT stores records for any number of topics and a limited
number of records for each topic (MaxEntriesPerTopic). The list of records for a
particular topic is called the *topic queue* because it functions like a FIFO queue of
length MaxEntriesPerTopic. Each record is essentially the content of the ping packet: It
contains the public key, IP endpoint of the node as well as a timestamp.

There is also a global limit on the number of records regardless of the topic queue which
contains them (MaxEntries). When the MaxEntries limit is reached, the last entry of the
least recently requested topic queue is removed.

For each topic queue, the registrar maintains a *wait period*. This value acts as a valve
controlling the influx of new registrations. Registrant nodes communicate interest to
register a topic in the ping packet and receive a *waiting ticket* which they can use to
register after the period has passed. Since protocol semantics require ping packets for
other purposes (e.g. node liveness checks), registrants re-learn the wait period values
automatically.

The wait period for each queue is assigned based on the amount of sucessful registrations.
It is adjusted such that registrations will stay in the topic queue for approximately 10
minutes.

```python
targetRegistrationLifetime = 600  # 10 min
targetRegistrationInterval = targetRegistrationLifetime / len(queue)
controlLoopConstant = 600  # arbitrary

period = now() - queue.timeOfLastSuccessfulRegistration()
newWP = w.currentWaitPeriod * exp((targetRegistrationInterval - period) / controlLoopConstant)
w.currentWaitPeriod = max(newWP, minWaitPeriod)
```

If a node was previously registered, it is prevented from registering again for a certain
amount of time, the NoTicketTime. Upon sucessful registration, this time is assigned from
an exponential random distribution.

```python
avgNoTicketTime = 600  # 10 min
node.noTicketTime = expRand() * avgNoTicketTime
```

#### Registration

Each registrar node assigns its per-topic wait period as a function of registration
frequency. Globally speaking, there is a per-topic *radius* which is the address prefix of
a subset of registrar nodes where the average waiting period is close to the ideal waiting
period. The basic packet validity checks ensure that only registrations with a valid
signature are accepted.

The registrant continuously registers itself for each topic it provides, approximating the
radius. Each registrant has a target waiting period which it tries to approach. It tries
to find registrar nodes which offer a short waiting period and which are located inside
the currently approximated radius.

The registrant initially assumes that the topic radius is equivalent to the size of the network.
The approximation will shrink down rapidly during the first few rounds of registration.

```python
targetWaitPeriod = ask Zsolt
radii = {}

def approximatedRadius(topic):
    # initial radius approximation is entire network
    if topic not in radii:
        return 2*256
    return radii[topic]

def adjustRadius(topic, pong):
    if pong.hasWaitPeriod(topic):
        r = approximatedRadius(topic)
        adj = 0.99 if pong.waitPeriodFor(topic) < targetWaitPeriod else 1.01
        radii[topic] = max(r * adj, minimumRadius)
```

In order to actually register, waiting tickets (pong packets) must be collected from
possible registrars. The collection procedure, given below, runs for each topic and
collects from registrar nodes such that the resulting registrations will fulfill the
desired redundancy. Even though tickets are collected separately for each topic, the list
of active tickets is shared among all topics.

```python
tickets = []
targetRegistrationLifetime = 600  # 10min

def collectTickets(topic, redundancy):
    while True:
        target = keccak256(topic) ^ randomNumberBelow(approximatedRadius(topic))
        closestNodes = kademliaLookup(target)
        for n in closestNodes:
            # Collect waiting ticket if we don't have one
            # from this node yet.
            if hasTicketFromNode(tickets, n):
                pong = ticketFromNode(tickets, n)
            else:
                pong = ping(n, allTopics)
                tickets.add(pong)
                
            # Adjust the radius approximation.
            adjustRadius(topic, pong)
                
        # Pause collection if we have enough tickets for the
        # immediate future.
        window = now() + 2*targetWaitPeriod
        def ticketsInWindow():
            return [ t for t in tickets if t.waitPeriodEndTime(topic) < window ]
        desiredRegistrationFrequency = redundancy / targetRegistrationLifetime
        while len(ticketsInWindow()) > window*desiredRegistrationFreq:
            sleep(1)
```

Registrants can use the collected tickets to register after their waiting period has passed.
For simplicity all collected tickets are used.

```python
def register():
    while True:
        ticket = waitForNextTicket(tickets)
        sendTopicRegisterPacket(ticket.node, allTopics, ticket)
        tickets.remove(ticket)
```

#### Finding Nodes

Finding nodes that provide a certain topic is a continuous process which reads the content
of topic queues inside the approximated topic radius. Nodes within the radius are
contacted with topicQuery packets. Collecting tickets and waiting on them is not required.

The approximated topic radius value can be shared with the registration algorithm if the
the same topic is being registered and searched for.

```python
recentlyAsked = []

def findTopicNodes(topic):
    result = []
    target = keccak256(topic) ^ randomNumberBelow(approximatedRadius(topic))
    closestNodes = kademliaLookup(target)
    for n in closestNodes:
        if n not in recentlyAsked:
            # Update the topic radius approximation.
            # A real implementation could reuse a recently
            # received pong packet.
            pong = ping(n, allTopics)
            recentlyAsked.add(node)
            adjustRadius(topic, pong)
            
            # Get the content of n's topic queue.
            result += topicQuery(n, topic)
        
        # Keep the set of recently asked nodes below some arbitrarily
        # chosen size.
        if len(recentlyAsked) > 10000:
            recentlyAsked.pop()
    
    return result
```

#### Changes to the Node Discovery Protocol

**ping Packet (0x01)**

```text
ping  = [ version, fromAddr, toAddr, expTimestamp, [ "topics", [ topic, ... ], ... ] ]
topic = [ bytes, ... ]
```

In v5, the ping packet gains an additional element containing topics through which the
requester queries the wait period for each topic. Note that the number of topics that can
be supplied is limited by the 1280 byte packet size.

**pong Packet (0x02)**

```text
pong = [ toAddr, echo, expTimestamp, known, topicsHash, [ waitPeriod, ... ] ]
echo = <keccak256 hash of ping packet>
toAddr = <recipient IP endpoint>
waitPeriod = <earliest time of next registration>
topicsHash = keccak256(RLP([ topic, ... ]))
```

TODO: serial
TODO: explain why serial is needed

The pong packet is an unforgeable reply to the ping packet. It also acts as a registration
waiting ticket for the topics requested in the ping packet.

* `known` is 0 if the sender was previously unknown and 1 otherwise.
* The hash of the topic list contained in the ping packet.
* The wait period values for each topic requested in the ping packet.

**findnodeHash Packet (0x05)**

```text
findnodeHash = [ target, expTimestamp ]
target = <256bit hash>
```

In addition to the v4 findnode packet, v5 introduces a way to find nodes close to a hash.
The v4 findnode packet is deprecated and should only be used for communication with
discovery v4 nodes.

**topicRegister Packet (0x06)**

```text
topicRegister = [ [ topic, ... ], pong ]
```

The topicRegister packet adds the sender to the topic queue for each supplied topic.
Registrations are only accepted if the waiting period has passed and the ticket
authenticates all given topics and waitPeriods.

**topicQuery Packet (0x07)**

Topic queries are facilitated by a two new packet types, topicQuery and topicNodes.

```text
topicQuery = [ topic, expTimestamp ]
```

The topicQuery packet requests the content of a topic queue. Similar to the v4
findNeighbours packet, topicQuery packets should only be replied to if the sender has
previously proven control of the sender IP address and node key by exchange of ping/pong
packets in both directions.

**topicNodes Packet (0x08)**

```text
topicNodes = [ echo, [ node, ... ] ]
echo = <keccak256 hash of topicQuery query>
node = [ IP, UDP, TCP, ID ]
```

topicNodes is the reply to the topicQuery packet.

### Motivation

Our current approach to finding peers is to connect to random nodes found in the DPT. This
strategy has been chosen because it is resilient and the resulting network graph performs
well for propagation of Ethereum blocks and transactions.

There are cases where connecting randomly doesn't work very well. A client interested in a
blockchain other than the one run by the main network finds peers only slowly because it
will meet many more main net nodes than nodes it actually cares about. Random connections
also don't cater to the needs of asymmetric protocols such as the Ethereum Light Client
Protocol (LES), where a node is interested in finding servers that can supply data but
cannot offer any data in return.

In order to address these issues, the discovery protocol should be adapted to carry more
information about individual nodes and provide a scalable way to find other nodes who are
interested in similar content or which can offer a certain service.

### Rationale

Compared to the existing v4 `neighbours` packet, `topicNodes` contains a reference to the
request. This change helps distinguish concurrent queries and prevents replay.

Node topics are not distributed uniformly. Topic association storage must scale to the
needs of very popular topics as well as small topics with few participants. The storage
scheme presented in this EIP ensures that network-wide storage space increases with
popularity by increasing the bucket size for frequently requested records.

The chosen target wait period constant of 10 min is constrained by various factors:

* The chosen value directly affects the amout of UDP traffic generated by the protocol. A
  low value causes more reregistrations.
* A longer period prevents service providers from rapidly hopping on and off the network.
  A node which 'waits out' the period and which can maintain the same IP address for the
  duration is likely to be online for a longer period of time.
* An attacker trying to slow down operations by inserting many 'sybil' registrations must
  actually remember the pong packet for that long.
