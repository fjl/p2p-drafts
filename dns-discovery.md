---
eip: XXX
title: Node Discovery via DNS
author: Felix Lange <fjl@ethereum.org>, Péter Szilágyi <peter@ethereum.org>
type: Informational
category: Networking
status: Draft
created: 2018-09-26
requires: 778
---

# Abstract

This document describes a scheme for permissioned, authenticated, updateable
Ethereum node lists retrievable via DNS.

# Motivation

All known Ethereum clients contain hard-coded bootstrap node lists. Updating
those lists requires a software update. The current lists are small, giving the
client little choice of initial entry point into the Ethereum network. We would
like to maintain larger node lists containing hundreds of nodes, and update them
regularly.

The scheme described here is a replacement for client bootstrap node lists with
equivalent security and many additional benefits. The permissioned nature of the
scheme is comparable to current practice because client developers are in full
control of current bootstrap node lists and any further nodes reachable through
them.

DNS node lists may also be useful to Ethereum peering providers because their
customers can configure the client to use the provider's list. Finally, the
scheme serves as a fallback option for nodes which can't join the node discovery
DHT.

# Specification

## DNS Record Structure

Node lists are encoded as TXT records. The records form a merkle tree.

The root of the tree is a record with content

    enr-tree-root=v1 hash=<roothash> seq=<seqnum> sig=<signature>

where `roothash` is the root hash of the tree, a hexadecimal string of length
8, `seqnum` is a decimal integer and `signature` is a 65-byte secp256k1 EC
signature over the concatenation of `roothash` and `seqnum`.

Further TXT records map hashes to one of three types of value:

- `enr-tree=<h₁>,<h₂>,...,<hₙ>` is an intermediate tree containing further hashes.
- `enr=<node-record>` is a leaf containing a node record. The node record shall be
  encoded as a base85 string.
- `enr-tree-link=<fqdn>` is a leaf pointing to a different list located at another
  fully qualified domain name.

Example (in zone file format):

```text
; name            ttl    class type  content
@                 60     IN    TXT   "enr-tree-root=v1 hash=78019b5998661b1f seq=3 sig=76d9f2f2f66b415868768302b8824fde9afb28869cdb5e4dab967bff5013657c0a73830f34c1457691d3a3a002cee3bad4d455bb4b9e11941c447fab767f27cf01"
78019b5998661b1f  86400  IN    TXT   "enr-tree=d8555522d5d0bf89,4a89cf04b0aee42d,5b378d39913b1f93"
d8555522d5d0bf89  86400  IN    TXT   "enr=b'_<guQjUTCP{RqHWjGNW?LRl*ySR#tAhp%LQL3m%l>?Y;TWG<eXes@Z`*$>0`ztySi++YoiEfGsM%?UAj#)fmH0fK2{f_5~5X>f$g0C53{b7f<2GBq}9F`)y>V@$3MNvyO1*rdj`{)|<(4G~-P0Ct?gKo2rl%`rF'"
4a89cf04b0aee42d  86400  IN    TXT   "enr=b'_<guQI<5l3<MLpP%$R(Ut$~G6VBUTe_2<DP7@AynC@+0)M3P>A=|HjLA-MoVR+B&Rn&O{CUb#id6R~XaJiQj&0fK2{f_5~5X>f$bGh}0lb7f<2GBq}9F`)wOd@Tj%lD4x~phg<p>jjtP)0mE_TKMaV2tv>IW4Dk'"
5b378d39913b1f93  86400  IN    TXT   "enr-tree-link=morenodes.example.org"
```

## Building the tree

No particular ordering or structure is defined for the tree, but the content of
any TXT record should be small enough to fit into the 512 byte limit imposed on
UDP DNS packets. Whenever the tree is updated, its sequence number should
increase.

## Client Protocol

To find nodes at a given DNS name, say "nodes.example.org":

1. Resolve the TXT record of "nodes.example.org" and check whether it contains a valid
   "enr-tree-root=v1" entry. Let's say the root hash contained in the entry is "30b2f4".
2. Optionally verify the signature on the root against a known public key and
   check whether the sequence number is larger than or equal to any previous
   number seen for that name.
3. Resolve TXT record of the hash, "30b2f4.nodes.example.org". The next step
   depends on the string prefix of the record:
   - for `"enr-tree="`: parse the list of hashes and continue resolving those.
   - for `"enr="`: decode, verify the node record and import it to local node storage.
   - for `"enr-tree-link="`: continue traversal on that name.

During traversal, the client should track hashes and names already resolved to
avoid going into an infinite loop.

# Rationale

Why DNS?

- never blocked by firewall
- edge caching
- no custom server needed, can deploy the tree to cloudflare, dnssimple, route53...
- DNS client built into to every OS

Why merkle tree structure?

- authentication of node list
- syncing updates to list is fast and bandwidth-efficient
- can be replicated to other name if one is blocked
- caching friendly: only root needs short TTL
- Encoding as a tree of names makes it work for setups where only basic UDP DNS
  is available because the individual records are small.

Why `enr-tree-link`?

- delegation allows federated management of node lists
- If two node lists link to each other, users can use either list and get nodes
  from both.

Security considerations:

Hash names protect the integrity of the list even without DNSSEC. At worst,
intermediate resolvers can block access to the list or disallow updates to it,
but cannot corrupt its content. The sequence number prevents replacing the root
with an older version.
