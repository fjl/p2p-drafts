# -*- coding: utf-8 -*-

import base64
import dns.resolver
import re
import rlp
import sha3
from collections import OrderedDict
from enr import ENR

# Resolvers

class SystemResolver():
    def resolveTXT(self, name):
        # print('Resolving ' + name)
        answers = dns.resolver.query(name, 'TXT')
        return [b''.join(rdata.strings).decode() for rdata in answers]

# URLs

def encode_url(domain, pubkey):
    user = to_base32(pubkey.format(compressed=True))
    return "enrtree://{}@{}".format(user, domain)

def decode_url(url):
    m = re.match('^enrtree://([a-zA-Z0-9]+)@([^\\s]+)$', url)
    if m == None:
        raise ParseError('invalid enrtree URL ' + url)
    host = m.group(2)
    try:
        pubkey = from_base32(m.group(1))
    except Exception:
        raise ParseError('invalid public key in URL ' + url)
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

    @classmethod
    def resolve(cls, name, resolver=SystemResolver()):
        tree = cls.__new__(cls)
        tree.entries, tree.root = {}, None
        tree.resolve_updates(name, resolver)
        return tree

    def resolve_updates(self, name, resolver=SystemResolver()):
        e = _resolveEntry(resolver, name)
        if isinstance(e, rootEntry):
            if self.root is None or e.roothash != self.root.roothash:
                self._resolve_missing(name, e.roothash, resolver)
                self.root = e
        else:
            raise RuntimeError('no tree found')

    def _resolve_missing(self, name, roothash, resolver):
        want = OrderedDict()
        want[roothash] = True
        new_entries = {}
        while len(want) > 0:
            h, _ = want.popitem(False)
            if h in self.entries:
                new_entries[h] = self.entries[h]
                continue
            # need this entry, resolve
            e = _resolveEntry(resolver, h + '.' + name, h)
            if isinstance(e, subtreeEntry):
                new_entries[h] = e
                for d in e.subdomains:
                    want[d] = True
            elif isinstance(e, enrEntry) or isinstance(e, linkEntry):
                new_entries[h] = e
        # done, set new entries
        self.entries = new_entries

def _resolveEntry(resolver, name, hash=None):
    for txt in resolver.resolveTXT(name):
        e = parse_entry(txt, hash)
        if e is not None:
            return e
    raise 'no entry found at ' + name

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
        return '{}{}@{}'.format(linkEntry.prefix, to_base32(self.pubkey), self.name)

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
        sighash = sha3.keccak_256(self.signed_text().encode()).digest()
        self.sig = privkey.sign_recoverable(sighash, hasher=None)

    def subdomain(self):
        return ''

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

def parse_entry(txt, hash=None):
    if hash != None and not _verify_hash(txt, hash):
        raise ParseError('hash of entry {} doesn\'t match "{}"'.format(hash, txt))
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

def _verify_hash(txt, hash):
    full = sha3.keccak_256(txt.encode()).digest()
    prefix = from_base32(hash)
    return full.startswith(prefix)

class ParseError(BaseException):
    pass

# Base32 Helpers

def to_base32(b):
    enc = base64.b32encode(b).decode()
    return enc.rstrip('=') # remove padding

def from_base32(s):
    if len(s) % 8: # add padding if needed
        s += ('=' * (8 - len(s) % 8))
    return base64.b32decode(s)
