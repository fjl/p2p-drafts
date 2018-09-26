# -*- coding: utf-8 -*-

import enr
import rlp
import base64
import sha3

def make_enr_tree(enrs, links, seq, privkey):
    leaves = list(map(enr_entry, enrs)) + list(map(link_entry, links))
    rhash, tree = subtree_entry([h for (h, _) in leaves])
    root = root_entry(rhash, seq, sign_root(privkey, rhash, seq))
    records = [("@", root), (hash_to_subdomain(rhash), tree)]
    return records + [(hash_to_subdomain(h), e) for (h, e) in leaves]

def to_zonefile(records):
    return "\n".join([
        "{:20}   IN    TXT   \"{}\"".format(h, e)
        for (h, e) in records
    ])

def enr_entry(enr):
    enc = enr.encode()
    txt = "enr=" + base64.b85encode(enc).decode()
    return (hash(enc), txt)

def link_entry(link):
    txt = "enr-tree-link=" + link
    return (hash(txt), txt)

def subtree_entry(hashes):
    txt = "enr-tree=" + ",".join([hash_to_subdomain(h) for h in hashes])
    return (hash(txt), txt)

def root_entry(rhash, seq, sig):
    sig = base64.b85encode(sig).decode()
    return "enr-tree-root=v1 hash={} seq={} sig={}".format(hash_to_subdomain(rhash), seq, sig)

def sign_root(privkey, rhash, seq):
    sighash = sha3.keccak_256((rhash.hex() + str(seq)).encode()).digest()
    return privkey.sign_recoverable(sighash, hasher=None)

def hash_to_subdomain(hash):
    return hash[:8].hex()

def hash(entry):
    if isinstance(entry, str):
        entry = entry.encode()
    return sha3.keccak_256(entry).digest()
