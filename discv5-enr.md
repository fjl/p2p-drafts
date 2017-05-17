# Preamble

    EIP: XXX
    Title: Signed Ethereum Node Records (ENR)
    Author: Felix Lange <fjl@ethereum.org>
    Type: Standard Track
    Category Networking
    Status: Draft
    Created: 2017-05-17

# Abstract

This EIP defines Signed Ethereum Node Records, an open format for p2p connectivity
information.

# Motivation

Ethereum nodes discover each other through the node discovery protocol. The purpose of
that protocol is relaying node identity public keys (on the secp256k1 curve), their IP
address and two port numbers. No other information can be relayed.

This specification seeks to lift the restrictions of the discovery v4 protocol by defining
a flexible format, the *node record*, for connectivity-related information. Node records
can be relayed through a future version of the node discovery protocol. They can also be
relayed through arbitrary other mechanisms such as DNS, ENS, a devp2p subprotocol, etc.

Node records improve cryptographic agility and handling of protocol upgrades. A record can
contain information about arbitrary transport protocols and public key material associated
with them.

Another goal of the new format is to provide authoritative updates of connectivity
information. If a node changes its endpoint and publishes a new record, other nodes should
be able to determine which record is newer.

# Specification

The components of a node record are:

 - `signature`: cryptographic signature of record contents made by the node identity key.
 - `seq`: A sequence number. Nodes should increase the number whenever the record changes.
-  The remainder of the record consists of arbitrary key/value pairs.

### RLP Encoding

The canonical encoding of a node record is an RLP list of `[signature, seq, k, v, ...]`.
The maximum encoded size of a node record is 300 bytes. Implementations should reject
records larger than this size.

Defined Key Value Pairs:

  - key: "id", value: "secp256k1"
  - key: "secp256k1", value: (compressed) secp256k1 public key
  - key: "ip4", value: IPv4 address, 4 bytes
  - key: "ip6", value: IPv4 address, 4 bytes
  - key: "discv5", value: UDP port for discovery v5, 2 bytes

Records are signed and encoded as follows:

    content   = rlp(seq) || rlp(k) || rlp(v) || ...
    signature = rlp(sign(keccak256(content)))
    record    = rlp_list(signature || content)

# Rationale

# Copyright

Copyright and related rights waived via CC0.
