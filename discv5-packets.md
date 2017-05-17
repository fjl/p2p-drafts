## Packet Types

### Handshake Packet (0x01)

  `[signature, reply-cookie, recipient-ip-port, wantreply]`
  
  The `signature` is used to authenticate the reply.

### FindNode Packet (0x02)

  `[target-hash]`

### Neighbors Packet (0x03)

  `[reply-cookie, node-record+]`

### RequestTicket Packet (0x04)

  `[topic]`

### TicketPacket (0x05)

  `[auth-cookie, node-public-key, timestamp, serial, topic, wait-period]`

`auth-cookie` is used by the issuer to authenticate the ticket when it is
presented as part of a TopicRegister packet.
  
### TopicRegister Packet (0x06)

  `[ticket, registration-signature]`
  
The `registration-signature` proves that the sender actually registered for that topic.
The recipient should verify that the signature was made by the public key in the ticket.
    
### TopicQuery Packet (0x07)

  `[topic]`
    
Requests that nodes which are registered for the given topic should be sent in a
TopicNodes packet.
    
### TopicNodes Packet (0x08)

  `[reply-cookie, ["kad", node-id-hash]+]`
  
Contains the node ids which have registered for the topic. Recipients should resolve the
node ids through Kademlia to find the actual node metadata for each query result. The
result includes the "kad" identifier with each node id hash to permit extensions in a
future protocol version.

