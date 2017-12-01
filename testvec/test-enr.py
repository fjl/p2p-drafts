# -*- coding: utf-8 -*-

from .enr import ENR

import ecdsa

privkey_hex = 'b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291'
privkey = ecdsa.SigningKey.from_string(bytes.fromhex(privkey_hex), curve=ecdsa.SECP256k1)

def test_encode_decode():
    e = ENR().set('ip4', '127.0.0.1').set('discv5', 30303)
    e.sign(privkey)
    enc = e.encode()
    print('Record:\n  ', e)
    print('RLP ({} bytes):\n  '.format(len(enc)), enc.hex())
    print('Signing pubkey:\n  ', e.get('secp256k1').hex())
    print('Node address:\n  ', e.node_addr().hex())

    e2 = ENR.from_rlp(enc)
    print("Decoded Record:\n  ", e2)
