# -*- coding: utf-8 -*-

import coincurve
import dnsdisc
from enr import ENR

def test_enr_tree_example():
    keys = [
        coincurve.PrivateKey.from_hex('b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291'),
        coincurve.PrivateKey.from_hex("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a"),
        coincurve.PrivateKey.from_hex("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee"),
        coincurve.PrivateKey.from_hex("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"),
    ]
    enrs = [
        ENR().set("ip", "203.0.113.1").sign(keys[0]),
        ENR().set("ip", "198.51.100.99").sign(keys[1]),
    ]
    links = [
        "morenodes.example.org",
    ]
    tree = dnsdisc.make_enr_tree(enrs, links, 3, keys[2])

    print("Example zone file:\n")
    print(dnsdisc.to_zonefile(tree))
    print("\n\n")
