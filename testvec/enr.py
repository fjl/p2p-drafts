# -*- coding: utf-8 -*-

import rlp
import socket
import ecdsa
import sha3
import base64

from bitcoin import encode_pubkey, decode_pubkey
from rlp.utils import bytes_to_str


# codecs for common properties
KV_CODECS = {
   'ip4': {
        'encode': socket.inet_aton,
        'decode': socket.inet_ntoa,
    },
    'discv5': {
        'encode': rlp.utils.int_to_big_endian,
        'decode': rlp.utils.big_endian_to_int,
    },
}


class ENR:
    _kv, _sig, _raw = {}, None, None

    def __init__(self, seq=0):
        assert(isinstance(seq, int) and seq >= 0)
        self._seq = seq

    @property
    def seq(self):
        return self._seq

    def get(self, k):
        if k in self._kv:
            v = self._kv[k]
            if k in KV_CODECS:
                v = KV_CODECS[k]['decode'](v)
            return v

    def set(self, k, v):
        self._raw, self._sig = None, None # any change invalidates signature
        if k in KV_CODECS:
            v = KV_CODECS[k]['encode'](v)
        self._kv[k] = v
        return self

    def delete(self, k):
        self._raw, self._sig = None, None # any change invalidates signature
        del self._kv[k]

    def sign(self, privkey):
        self._seq = self._seq + 1
        self.set('id_secp256k1', compress_secp256k1_pubkey(privkey.get_verifying_key()))
        self._sig, self._raw = self.sign_and_encode(privkey)
        return self

    def sign_and_encode(self, privkey):
        content = self._content()
        sig = privkey.sign_deterministic(content, hashfunc=sha3.keccak_256)
        rec = rlp.encode(sig) + content
        raw = rlp.codec.length_prefix(len(rec), 0xc0) + rec
        return (sig, raw)
    
    def _content(self):
        kv = [ rlp.encode(k) + rlp.encode(v) for (k, v) in sorted(self._kv.items()) ]
        return rlp.encode(self._seq) + b''.join(kv)
    
    def encode(self):
        if self._raw is None:
            raise 'no signature, call sign first'
        return self._raw

    @classmethod
    def from_rlp(cls, data):
        assert(len(data) <= 200) # check max size
        elems = rlp.decode(data)
        assert(isinstance(elems, list))
        assert(len(elems) >= 2 and len(elems)%2 == 0)

        seq = rlp.utils.big_endian_to_int(elems[1])
        e = cls(seq)
        e._raw, e._sig = data, elems[0]
        e._kv = cls._decode_kv(elems[2:])
        e._check_signature()
        return e

    @classmethod
    def _decode_kv(cls, list):
        kv = {}
        prev = None
        for i in range(0, len(list), 2):
            key = bytes_to_str(list[i])
            if i > 0 and key < prev:
                raise 'k/v keys are not sorted'
            kv[key] = list[i+1]
            prev = key
        return kv

    def _check_signature(self):
        # remove list header and signature to get signed content
        _, _, e = rlp.codec.consume_length_prefix(self._raw, 0)
        _, e = rlp.codec.consume_item(self._raw, e)
        content = self._raw[e:]
        # verify against the public key from k/v data
        id = self.get('id_secp256k1')
        assert(id is not None)
        pub = decompress_secp256k1_pubkey(id)
        pub.verify(self._sig, content, hashfunc=sha3.keccak_256)
    
    def __str__(self):
        kv = {k: self.get(k) for k in sorted(self._kv.keys())}
        return '<ENR seq={} {}>'.format(self.seq, kv)

    def url(self):
        return 'enr:' + base64.urlsafe_b64encode(self.encode()).decode('ascii')


def compress_secp256k1_pubkey(pub):
    p = pub.pubkey.point
    return encode_pubkey((p.x(), p.y()), 'bin_compressed')

def decompress_secp256k1_pubkey(data):
    x, y = decode_pubkey(data, 'bin_compressed')
    p = ecdsa.ellipticcurve.Point(ecdsa.SECP256k1.curve, x, y)
    return ecdsa.VerifyingKey.from_public_point(p, ecdsa.SECP256k1)
    
