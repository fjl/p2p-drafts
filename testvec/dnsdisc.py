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
        answers = dns.resolver.query(name, 'TXT')
        return [b''.join(rdata.strings).decode() for rdata in answers]

# The Tree

class Tree():
    def __init__(self, enrs, links, seq):
        leaves = list(map(enrEntry, enrs)) + list(map(linkEntry, links))
        entries = self._build(leaves)
        self.entries = {e.subdomain(): e for e in entries + leaves}
        roothash = entries[0].subdomain()
        self.root = rootEntry(roothash, seq, None)

    @classmethod
    def with_root(cls, root):
        tree = cls.__new__(cls)
        tree.root = root
        tree.entries = {}
        return tree

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
        e = _resolveEntry(resolver, name)
        if isinstance(e, rootEntry):
            tree = cls.with_root(e)
            tree.resolve_updates(name, resolver)
            return tree
        else:
            raise 'no tree found'

    def resolve_updates(self, name, resolver=SystemResolver()):
        want = OrderedDict()
        want[self.root.roothash] = True
        new_entries = {}
        while len(want) > 0:
            h, _ = want.popitem(False)
            if h in self.entries:
                new_entries[h] = e
                continue
            # need this entry, resolve
            e = _resolveEntry(resolver, h + '.' + name)
            if isinstance(e, subtreeEntry):
                new_entries[h] = e
                for d in e.subdomains:
                    want[d] = True
            elif isinstance(e, enrEntry) or isinstance(e, linkEntry):
                new_entries[h] = e
        # done, set new entries
        self.entries = new_entries

    def to_zonefile(self):
        rr = ['{:20}   60      IN    TXT   "{}"'.format('@', self.root.text())]
        rc = ['{:20}   86900   IN    TXT   "{}"'.format(e.subdomain(), e.text()) for e in self.entries.values()]
        return '\n'.join(rr + rc)

def _resolveEntry(resolver, name):
    for txt in resolver.resolveTXT(name):
        e = parse_entry(txt)
        if e is not None:
            return e
    raise 'no entry found at ' + name

# Tree Entries

_HASH_ABBREV = 8
_MAX_INTERMEDIATE_HASHES = round(300 / (_HASH_ABBREV*2))

class entry():
    def hash(self):
        return sha3.keccak_256(self.text().encode()).digest()

    def subdomain(self):
        return self.hash()[:_HASH_ABBREV].hex()

class enrEntry(entry):
    prefix = 'enr='

    def __init__(self, enr):
        self.enr = enr

    def text(self):
        enc = self.enr.encode()
        return enrEntry.prefix + base64.b85encode(enc).decode()

    @classmethod
    def parse(cls, txt):
        raw = base64.b85decode(txt[len(cls.prefix):])
        return cls(ENR.from_rlp(raw))

class linkEntry(entry):
    prefix = 'enr-tree-link='

    def __init__(self, link):
        self.link = link

    def text(self):
        return linkEntry.prefix + self.link

    @classmethod
    def parse(cls, txt):
        return cls(txt[len(cls.prefix):])

class subtreeEntry(entry):
    prefix = 'enr-tree='

    def __init__(self, subdomains):
        self.subdomains = subdomains

    def text(self):
        return subtreeEntry.prefix + ','.join(self.subdomains)

    @classmethod
    def parse(cls, txt):
        return cls(txt[len(cls.prefix):].split(','))

class rootEntry(entry):
    prefix = 'enr-tree-root=v1'

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
        sig = base64.b85encode(self.sig).decode()
        return self.signed_text() + ' sig=' + sig

    def signed_text(self):
        return '{} hash={} seq={}'.format(rootEntry.prefix, self.roothash, self.seq)

    pattern = re.compile(re.escape(prefix) + ' hash=([0-9a-fA-F]{16}) seq=([0-9]+) sig=(.+)')

    @classmethod
    def parse(cls, txt):
        m = cls.pattern.match(txt)
        try:
            roothash = m.group(1)
            seq = int(m.group(2))
            sig = base64.b85decode(m.group(3))
        except Exception:
            raise ParseError('invalid tree root ' + txt)
        if len(roothash) != 16:
            raise ParseError('invalid root hash length')
        if len(sig) != 65:
            raise ParseError('invalid signature length')
        return cls(roothash, seq, sig)

def parse_entry(txt):
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

class ParseError(BaseException):
    pass
