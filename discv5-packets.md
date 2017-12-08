# Preamble

    EIP: XXX
    Title: Node Discovery Protocol Version 5
    Author: Zsolt Felfoldi <zsolt@ethereum.org>, Felix Lange <fjl@ethereum.org>
    Type: Standard Track
    Category Networking
    Status: Draft
    Created: 2017-05-17

Links to other EIPs, update before publication:

[eip-enr]: ./discv5-enr.md
[eip-topics]: ./discv5-topics.md

# Abstract

This EIP defines Node Discovery Protocol Version 5. The specification defines a concrete
wire format and expected semantics for all packets.

# Specification

### Kademlia Database

Nodes participating in the discovery protocol form a Kademlia-like DHT. Unlike Kademlia,
the DHT does not store arbitrary key/value pairs. The purpose of the DHT is associating
node identifiers with node records as defined in [EIP 778][eip-enr].

Node identitifiers are public keys. The distance between two node keys is computed by
XORing the keccak-256 hashes of the encoded public keys.

    distance(pub₁, pub₂) = keccak256(pub₁) ⊻ keccak256(pub₂)

Each node maintains a routing table of up to 256 k-buckets containing the node records of
neighboring nodes according to the XOR distance metric. The bucket size `k` is defined to
be 16 like in protocol version 4. Routing table maintance follows the Kademlia paper:
entries in each bucket in the table are sorted according to the time of last contact with
the entry. Any valid communication with the entry moves it to the front of the bucket.

To find a node which is close to a particular target, nodes perform recursive lookups
using the FindNode packet. In a lookup, the target is approached by sending out FindNode
requests to the closest known nodes. When a `Neighbors` response arrives, more FindNode
requests are sent to the closest nodes from the result set until no closer nodes can be
discovered.

### Topic Index

In addition to the Kademlia routing table, nodes should also maintain a varying number of
topic queues as described in [EIP XXX][eip-topics]. Each topic queue stores node
identifiers belonging to a particular topic.

### Publishing Node Records

Nodes are responsible for publishing their own node record in the DHT. Node records
contain a sequence number, which is increased with each change to the record. Publishing
works by sending a signed node record in the Hey packet. The recipient of the Hey
packet updates its local copy of the record if it contains a larger sequence number than
any previously known record for the sender.

To publish the Internet-facing endpoint of the local node, it must be known locally. This
is achieved by observing the recipient IP and port of incoming Hey packets. When an
endpoint change is observed -- IP and port received in several Hey packets don't match
the currently published version of the local record -- the node should publish a new
version of the record containing the updated endpoint.

New versions of the local node record may also be published for other reasons, e.g. if
there are changes to non-discovery connection metadata in the record.

### Requests And Replies

With the exception of Hey, the defined packet types come in pairs where one packet type is
the request and the subsequently-numbered type is the reply. Packets designated as replies
contain a *reply cookie* which is computed as the first 16 bytes of the keccak256 hash of
the entire request packet.

Request packets other than Hey should not be processed unless the requester's endpoint
has recently been verified by the endpoint proof procedure (described below).

Implementations should enforce a reasonable timeout for request/reply interaction. The
recommended timeout is 500ms. Timed-out requests should not be retried. If a node is
sufficiently unresponsive, it should be removed from the Kademlia table and topic queues.

### Endpoint Proof

To prove that a particular node is actively participating in the discovery protocol using
a certain UDP endpoint, it must send a Hey reply packet (with cookie) from that endpoint.

### Record Relay Rules

To avoid relaying spam records, implementations must place restrictions on node records
that are to be relayed.

Implementation must check the signature of all records and reject any records with invalid
signature.

When receiving a record in a Hey packet, the record's node address must match the sender
and the IPv4 or IPv6 address and discovery port of the record (if present) must match the
source address of the UDP packet containing it. Records without IP and port must not be
relayed.

When receiving a record in a Neighbors packet, the IP address of the record must not cross
defined network boundaries, i.e.

* Implementations should reject records containing a loopback address in UDP packets from
  remote hosts.
* Implementations should also reject records containing a local area network address from
  hosts on the Internet.

### Packets

Discovery Protocol packets are sent using UDP. A single packet must not exceed 1280 bytes.

Packets are encoded as the RLP list  [`nonce, type, content]`, where

   * `nonce` is 16 random bytes
   * `type` is a single byte identfying the type of packet
   * `content` is an RLP-encoded list specific to each packet type

Valid packet types and their content are described below:

#### Hey Packet (0x01)

  `[signature, reply-cookie, [recipient-ip, recipient-port], wantreply, node-record]`

  Hey is a multi-purpose packet used for publishing of node records, endpoint proofs and
  node liveness checks. Hey can be sent at any time.
  
  - `signature` is used to authenticate the reply.
  - `reply-cookie` should be the abbreviated hash of the last Hey packet to which this
    packet is a response.
  - `[recipient-ip, recipient-port]` is the UDP envelope address to which the packet is
    being sent.
  - `wantreply` is `1` if the sender wishes to receive a reply and `0` otherwise.
  - `node-record` is the current version of the sender's signed node record. The record
    can be an empty byte array in case the node does not wish to publish or update its
    record.

#### FindNode Packet (0x02)

  `[target-hash]`

FindNode requests a Neighbors packet containing the closest known nodes to the target hash.

#### Neighbors Packet (0x03)

  `[reply-cookie, node-record+]`

The Neighbors packet is the reply to FindNode and contains known records of nodes
which are close to the target hash given in the request.

#### RequestTicket Packet (0x04)

  `[topic]`

The RequestTicket packet asks for a topic registration ticket for the given topic.

#### TicketPacket (0x05)

  `[auth-cookie, node-public-key, timestamp, serial, topic, wait-period]`

* `auth-cookie` is used by the issuer to authenticate the ticket when it is presented as
  part of a TopicRegister packet. The content of `auth-cookie` is opaque and is usually
  created as a signature or HMAC of the ticket's content.
  
#### TopicRegister Packet (0x06)

  `[ticket, registration-signature]`
  
The `registration-signature` proves that the sender registered for that topic.
The recipient should verify that the signature was made by the public key in the ticket.

#### TopicQuery Packet (0x07)

  `[topic]`
    
Requests that nodes which are registered for the given topic should be sent in a
TopicNodes packet.
    
#### TopicNodes Packet (0x08)

  `[reply-cookie, ["kad", node-id-hash]+]`
  
Contains the node ids which have registered for the topic. Recipients should resolve the
node ids through Kademlia to find the actual node metadata for each query result. The
result includes the "kad" identifier with each node id hash to permit extensions in a
future protocol version.

# Rationale

### Differences To Version 4

Discovery Protocol Version 4 defined the Kademlia-based routing table and not much else.
Compared to the previous version, the protocol in this document contains several important
improvements:

* The endpoint proof is not specified for version 4, but most implementations require a
  ping/pong interaction before findnode. Version 5 improves this by defining endpoint proofs.
* Version 4 packets contain timestamps to prevent packet replay. Timestamps are verified
  by checking that they're within a few seconds of the local clock. This has created many
  issues because most node's clocks are not accurate. In version 5, replay is prevented
  through the reply cookie and mandatory node endpoint checks.
* Version 4 packets are signed by the nodes static public key. Creating signatures
  isn't free and the cost of signing all packets is measurable on smaller devices. Version
  5 attempts to reduce the amount of signing where possible.
* Version 4 nodes can publish their IP address, discovery UDP port and RLPx TCP port, but
  no other metadata. In version 5, metadata is encoded using extensible node records.
* Use of ENR also solves the problem of reliable endpoint updates: a version 4 node cannot
  decide whether a received neighbor's endpoint information is newer than any locally
  stored endpoint and must resort to ping/pong to revalidate. In version 5, a node record
  received through neighbors can update local information because records contain a signed
  sequence number.

# Copyright

Copyright and related rights waived via CC0.
