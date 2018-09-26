# -*- coding: utf-8 -*-

import enr
import rlp
import base64
import sha3

def make_enr_tree(enrs, links, seq, privkey):
    leaves = list(map(enr_entry, enrs)) + list(map(link_entry, links))
    rhash, tree = subtree_entry([h for (h, _) in leaves])
    sighash = sha3.keccak_256((rhash + str(seq)).encode()).digest()
    sig = privkey.sign_recoverable(sighash, hasher=None)
    root = root_entry(rhash[:16], seq, sig)
    records = [("@", root), (rhash[:16], tree)] + [(h[:16], e) for (h, e) in leaves]
    return records

def to_zonefile(records):
    return "\n".join([
        "{:20}   IN    TXT   \"{}\"".format(h, e)
        for (h, e) in records
    ])

def enr_entry(enr):
    enc = enr.encode()
    txt = "enr=" + str(base64.b85encode(enc))
    return (hash(enc), txt)

def link_entry(link):
    txt = "enr-tree-link=" + link
    return (hash(txt), txt)

def subtree_entry(hashes):
    txt = "enr-tree=" + ",".join([h[:16] for h in hashes])
    return (hash(txt), txt)

def root_entry(hash, seq, sig):
    return "enr-tree-root=v1 hash={} seq={} sig={}".format(hash[:16], seq, sig.hex())

def hash(entry):
    if isinstance(entry, str):
        entry = entry.encode()
    return sha3.keccak_256(entry).digest().hex()
