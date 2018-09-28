# -*- coding: utf-8 -*-

import coincurve
import dnsdisc
import dns.resolver
from enr import ENR

testkeys = [
    coincurve.PrivateKey.from_hex('b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291'),
    coincurve.PrivateKey.from_hex('8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a'),
    coincurve.PrivateKey.from_hex('49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee'),
    coincurve.PrivateKey.from_hex('45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8'),
]

def test_url():
    url = dnsdisc.encode_url('nodes.example.org', testkeys[2].public_key)
    assert(url == 'enrtree://AP62DT7WOTEQZGQZOU474PP3KMEGVTTE7A7NPRXKX3DUD57TQHGIA@nodes.example.org')

def test_tree_example():
    enrs = [
        ENR().set('ip', '203.0.113.1').sign(testkeys[0]),
        ENR().set('ip', '198.51.100.99').sign(testkeys[1]),
    ]
    links = ['enrtree://AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@morenodes.example.org']
    tree = dnsdisc.Tree(enrs, links, 3).sign(testkeys[2])
    print('Example zone file:\n')
    print(to_zonefile(tree))
    print('\n\n')

def test_tree_resolve():
    ns = DictResolver('nodes.example.org', {
        '':                           'enrtree-root=v1 hash=TO4Q75OQ2N7DX4EOOR7X66A6OM seq=3 sig=96qJbnF0CMEk369OU1ZNC6tTBum9TGX7RWyvYDiSG310-lJQx-CxehTmn31DzeeYrL07FgeXKfp_ADfSoKyqjgA=',
        'TO4Q75OQ2N7DX4EOOR7X66A6OM': 'enrtree=F4YWVKW4N6B2DDZWFS4XCUQBHY,JTNOVTCP6XZUMXDRANXA6SWXTM,JGUFMSAGI7KZYB3P7IZW4S5Y3A',
        'F4YWVKW4N6B2DDZWFS4XCUQBHY': 'enr=-H24QI0fqW39CMBZjJvV-EJZKyBYIoqvh69kfkF4X8DsJuXOZC6emn53SrrZD8P4v9Wp7NxgDYwtEUs3zQkxesaGc6UBgmlkgnY0gmlwhMsAcQGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOA==',
        'JTNOVTCP6XZUMXDRANXA6SWXTM': 'enr=-H24QDquAsLj8mCMzJh8ka2BhVFg3n4V9efBJBiaXHcoL31vRJJef-lAseMhuQBEVpM_8Zrin0ReuUXJE7Fs8jy9FtwBgmlkgnY0gmlwhMYzZGOJc2VjcDI1NmsxoQLtfC0F55K2s1egRhrc6wWX5dOYjqla-OuKCELP92O3kA==',
        'JGUFMSAGI7KZYB3P7IZW4S5Y3A': 'enrtree-link=AM5FCQLWIZX2QFPNJAP7VUERCCRNGRHWZG3YYHIUV7BVDQ5FDPRT2@morenodes.example.org',
    })
    tree = dnsdisc.Tree.resolve('nodes.example.org', ns)
    assert(ns.querycount == 5)
    assert(len(tree.entries) == 4)
    # Check that updating doesn't re-download the whole tree.
    ns.querycount = 0
    tree.resolve_updates('nodes.example.org', ns)
    assert(ns.querycount == 1)

def test_tree_big():
    enrs = [ENR().set('i', str(i).encode()).sign(testkeys[0]) for i in range(0, 500)]
    tree = dnsdisc.Tree(enrs, [], 3).sign(testkeys[2])


class DictResolver():
    def __init__(self, domain, d):
        self.d = {}
        self.querycount = 0
        for (k, v) in d.items():
            if k == '':
                k = domain
            else:
                k = k + '.' + domain
            self.d[k] = v

    def resolveTXT(self, name):
        self.querycount += 1
        if name not in self.d:
            raise dns.resolver.NXDOMAIN
        return [self.d[name]]

def to_zonefile(tree):
    rr = ['{:27}   60      IN    TXT   "{}"'.format('@', tree.root.text())]
    rc = ['{:27}   86900   IN    TXT   "{}"'.format(e.subdomain(), e.text()) for e in tree.entries.values()]
    return '\n'.join(rr + rc)
