# -*- coding: utf-8 -*-

import base64
import coincurve
import dns.resolver
import re
import rlp
import sha3

from coincurve import PublicKey
from enr import ENR

# Resolvers

class SystemResolver():
    def resolveTXT(self, name):
        # print('Resolving ' + name)
        try:
            answers = dns.resolver.query(name, 'TXT')
        except dns.resolver.NXDOMAIN:
            return []
        else:
            return [b''.join(rdata.strings).decode() for rdata in answers]

# URLs

def encode_url(domain, pubkey):
    user = to_base32(pubkey.format(compressed=True))
    return "enrtree://{}@{}".format(user, domain)

def decode_url(url):
    m = re.match('^enrtree://([a-zA-Z0-9]+)@([^\\s]+)$', url)
    if m == None:
        raise ParseError('invalid enrtree URL: ' + url)
    host = m.group(2)
    try:
        pubkey = PublicKey(from_base32(m.group(1)))
    except ValueError as e:
        raise ParseError('invalid public key in {}: {}'.format(url, e))
    return (host, pubkey)

# The Tree

class Tree():
    def __init__(self, enrs, links, seq):
        leaves = list(map(enrEntry, enrs)) + list(map(linkEntry, links))
        entries = self._build(leaves)
        self.entries = {e.subdomain(): e for e in entries + leaves}
        roothash = entries[0].subdomain()
        self.root = rootEntry(roothash, seq, None)

    def _build(self, entries):
        if len(entries) <= _MAX_INTERMEDIATE_HASHES:
            return [subtreeEntry([e.subdomain() for e in entries])]
        else:
            roots, all = [], []
            while len(entries) > 0:
                children = self._build(entries[:_MAX_INTERMEDIATE_HASHES])
                roots.append(children[0])
                all.extend(children)
                entries = entries[_MAX_INTERMEDIATE_HASHES:]
            return self._build(roots) + all

    def sign(self, privkey):
        self.root.sign(privkey)
        return self

    def records(self):
        for e in self.entries.values():
            if isinstance(e, enrEntry):
                yield e.enr

    def links(self):
        for e in self.entries.values():
            if isinstance(e, linkEntry):
                yield encode_url(e.name, e.pubkey)

    @classmethod
    def resolve(cls, url, resolver=SystemResolver()):
        tree = cls.__new__(cls)
        tree.entries, tree.root = {}, None
        tree.resolve_updates(url, resolver)
        return tree

    def resolve_updates(self, url, resolver=SystemResolver()):
        name, pubkey = decode_url(url)
        e = _resolveRoot(resolver, name, pubkey)
        if self.root is None or e.roothash != self.root.roothash:
            self._resolve_missing(name, e.roothash, resolver)
            self.root = e

    def _resolve_missing(self, name, roothash, resolver):
        want = {roothash}
        new_entries = {}
        while len(want) > 0:
            h = want.pop()
            if h in self.entries:
                # found in local tree, copy it over
                new_entries[h] = self.entries[h]
                continue
            # need this entry, resolve
            e = _resolveEntry(resolver, h + '.' + name, h)
            if isinstance(e, subtreeEntry):
                new_entries[h] = e
                want |= set(e.subdomains)
            elif isinstance(e, enrEntry) or isinstance(e, linkEntry):
                new_entries[h] = e
        # done, set new entries
        self.entries = new_entries

# Tree Entries

_HASH_ABBREV = 16
_MAX_INTERMEDIATE_HASHES = round(300 / (_HASH_ABBREV * (13/8)))

class entry():
    def hash(self):
        return sha3.keccak_256(self.text().encode()).digest()

    def subdomain(self):
        return to_base32(self.hash()[:_HASH_ABBREV])

class enrEntry(entry):
    prefix = 'enr='

    def __init__(self, enr):
        self.enr = enr

    def text(self):
        enc = self.enr.encode()
        return enrEntry.prefix + base64.urlsafe_b64encode(enc).decode()

    @classmethod
    def parse(cls, txt):
        raw = base64.urlsafe_b64decode(txt[len(cls.prefix):])
        return cls(ENR.from_rlp(raw))

class linkEntry(entry):
    prefix = 'enrtree-link='

    def __init__(self, url):
        self.name, self.pubkey = decode_url(url)

    def text(self):
        key = to_base32(self.pubkey.format(compressed=True))
        return '{}{}@{}'.format(linkEntry.prefix, key, self.name)

    @classmethod
    def parse(cls, txt):
        return cls('enrtree://' + txt[len(cls.prefix):])

class subtreeEntry(entry):
    prefix = 'enrtree='

    def __init__(self, subdomains):
        self.subdomains = subdomains

    def text(self):
        return subtreeEntry.prefix + ','.join(self.subdomains)

    @classmethod
    def parse(cls, txt):
        return cls(txt[len(cls.prefix):].split(','))

class rootEntry(entry):
    prefix = 'enrtree-root=v1'

    def __init__(self, roothash, seq, sig):
        self.seq = seq
        self.roothash = roothash
        self.sig = sig

    def sign(self, privkey):
        self.sig = privkey.sign_recoverable(self.hash(), hasher=None)

    def subdomain(self):
        return ''

    def hash(self):
        return sha3.keccak_256(self.signed_text().encode()).digest()

    def text(self):
        if self.sig is None:
            raise RuntimeError('tree is not signed')
        sig = base64.urlsafe_b64encode(self.sig).decode()
        return self.signed_text() + ' sig=' + sig

    def signed_text(self):
        return '{} hash={} seq={}'.format(rootEntry.prefix, self.roothash, self.seq)

    pattern = re.compile('^' + re.escape(prefix) + ' hash=([0-9a-zA-Z]{10,}) seq=([0-9]+) sig=(.+)$')

    @classmethod
    def parse(cls, txt):
        m = cls.pattern.match(txt)
        try:
            roothash = m.group(1)
            seq = int(m.group(2))
            sig = base64.urlsafe_b64decode(m.group(3))
        except Exception:
            raise ParseError('invalid tree root ' + txt)
        if len(sig) != 65:
            raise ParseError('invalid signature length')
        return cls(roothash, seq, sig)

def _parse_entry(txt, hash=None):
    if txt.startswith(rootEntry.prefix):
        return rootEntry.parse(txt)
    elif txt.startswith(subtreeEntry.prefix):
        return subtreeEntry.parse(txt)
    elif txt.startswith(enrEntry.prefix):
        return enrEntry.parse(txt)
    elif txt.startswith(linkEntry.prefix):
        return linkEntry.parse(txt)
    else:
        return None

def _resolveEntry(resolver, name, hash=None):
    for txt in resolver.resolveTXT(name):
        e = _parse_entry(txt, hash)
        if e is not None:
            _verify_hash(txt, name, hash)
            return e
    raise RuntimeError('no enrtree entry found at ' + name)

def _verify_hash(txt, name, hash):
    full = sha3.keccak_256(txt.encode()).digest()
    prefix = from_base32(hash)
    if not full.startswith(prefix):
        raise VerifyError('invalid entry at {} doesn\'t match hash'.format(name, full.hex()))

def _resolveRoot(resolver, name, pubkey):
    for txt in resolver.resolveTXT(name):
        e = _parse_entry(txt, hash)
        if isinstance(e, rootEntry):
            sig = _recoverable_to_der(e.sig)
            if sig is not None and pubkey.verify(sig, e.hash(), hasher=None):
                return e
            else:
                raise VerifyError('invalid signature in enrtree root at ' + name)
    raise RuntimeError('no enrtree root found at ' + name)

class ParseError(ValueError): pass
class VerifyError(ValueError): pass

# Base32, Crypto Helpers

def to_base32(b):
    enc = base64.b32encode(b).decode()
    return enc.rstrip('=') # remove padding

def from_base32(s):
    if len(s) % 8: # add padding if needed
        s += ('=' * (8 - len(s) % 8))
    return base64.b32decode(s)

def _recoverable_to_der(sig):
    try:
        sig = coincurve.ecdsa.deserialize_recoverable(sig)
    except ValueError:
        return None
    return coincurve.ecdsa.cdata_to_der(coincurve.ecdsa.recoverable_convert(sig))
