# -*- coding: utf-8 -*-

from .enr import ENR

import ecdsa

privkey_hex = 'b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291'
privkey = ecdsa.SigningKey.from_string(bytes.fromhex(privkey_hex), curve=ecdsa.SECP256k1)

def test_encode_decode():
    e = ENR().set('ip4', '127.0.0.1').set('discv5', 30303)
    e.sign(privkey)
    record = e.encode()
    print(e)
    print('RLP :: ({} bytes) {}'.format(len(record), record.hex()))

    e2 = ENR.from_rlp(record)
    print("decoded {}".format(e2))
