# -*- coding: utf-8 -*-

from .enr import ENR

import coincurve

privkey = coincurve.PrivateKey.from_hex('b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291')

def test_encode_decode():
    e = ENR().set('ip', '127.0.0.1').set('udp', 30303)
    e.sign(privkey)
    enc = e.encode()
    print('Record:\n  ', e)
    print('RLP ({} bytes):\n  '.format(len(enc)), enc.hex())
    print('Signing pubkey:\n  ', e.get('secp256k1').hex())
    print('Node address:\n  ', e.node_addr().hex())

    e2 = ENR.from_rlp(enc)
    print("Decoded Record:\n  ", e2)

# def test_go_interop():
#     enc = bytes.fromhex('f896b84062f4b42c32b8fad8fe40e4f2f2e0b6964e68e577905828998fd6a0279fa6c55e20a9b19ae709017eef4448d6dd9afd578fb64d5bbd2c80fbe723eb4bd4c9ffbb058664697363763582766082696490736563703235366b312d6b656363616b83697034847f00000389736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138')
#     r = ENR.from_rlp(enc)
#     print('From Go:')
#     print(r)
