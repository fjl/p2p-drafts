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

MAXSIZE = 300

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

    def node_addr(self):
        return sha3.keccak_256(self.get('secp256k1')).digest()

    def sign(self, privkey):
        self._seq = self._seq + 1
        self.set('id', 'secp256k1-keccak')
        self.set('secp256k1', compress_secp256k1_pubkey(privkey.get_verifying_key()))
        self._sig, self._raw = self.sign_and_encode(privkey)
        return self

    def sign_and_encode(self, privkey):
        content = self._content()
        sigcontent = rlp.encode(content)
        sig = privkey.sign_deterministic(sigcontent, hashfunc=sha3.keccak_256, sigencode=ecdsa.util.sigencode_der)
        rec = rlp.encode([sig] + content)
        return (sig, rec)
    
    def _content(self):
        return [self._seq] + [e for kv in sorted(self._kv.items()) for e in kv]
    
    def encode(self):
        if self._raw is None:
            raise 'no signature, call sign first'
        return self._raw

    @classmethod
    def from_rlp(cls, data):
        assert(len(data) <= MAXSIZE) # check max size
        elems = rlp.decode(data)
        assert(isinstance(elems, list))
        assert(len(elems) >= 2 and len(elems)%2 == 0)

        seq = rlp.utils.big_endian_to_int(elems[1])
        e = cls(seq)
        e._raw, e._sig = data, elems[0]
        e._kv = cls._decode_kv(elems[2:])
        e._check_signature(elems[1:])
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

    def _check_signature(self, siglist):
        # check identity scheme
        scheme = self.get('id')
        if scheme != b'secp256k1-keccak':
            raise 'unsupported identity scheme "' + scheme + '"'
        # verify against the public key from k/v data
        pub = decompress_secp256k1_pubkey(self.get('secp256k1'))
        pub.verify(self._sig, rlp.encode(siglist), hashfunc=sha3.keccak_256, sigdecode=ecdsa.util.sigdecode_der)
    
    def __str__(self):
        kv = {k: self.get(k) for k in sorted(self._kv.keys())}
        return '<ENR seq={} {}>'.format(self.seq, kv)

def compress_secp256k1_pubkey(pub):
    p = pub.pubkey.point
    return encode_pubkey((p.x(), p.y()), 'bin_compressed')

def decompress_secp256k1_pubkey(data):
    x, y = decode_pubkey(data, 'bin_compressed')
    p = ecdsa.ellipticcurve.Point(ecdsa.SECP256k1.curve, x, y)
    return ecdsa.VerifyingKey.from_public_point(p, ecdsa.SECP256k1)
    
