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

def test_tree_example():
    enrs = [
        ENR().set('ip', '203.0.113.1').sign(testkeys[0]),
        ENR().set('ip', '198.51.100.99').sign(testkeys[1]),
    ]
    links = ['morenodes.example.org',]
    tree = dnsdisc.Tree(enrs, links, 3).sign(testkeys[2])
    print('Example zone file:\n')
    print(tree.to_zonefile())
    print('\n\n')


def test_tree_resolve():
    ns = DictResolver('nodes.example.org', {
        '':                 'enr-tree-root=v1 hash=797a23d8100f7078 seq=3 sig=x<MqCoo*q-S?0wcg^F6}d^{)Y+8}zKrb=T*3)wWDA&{%R5&!lrGTKo@c*@~@Yoo&#+>bM^)@Y(v5}hf<00',
        '797a23d8100f7078': 'enr-tree=088bef4b06632cdb,eb9c1ad35aac9c71,5b378d39913b1f93',
        '088bef4b06632cdb': 'enr=_<guQjUTCP{RqHWjGNW?LRl*ySR#tAhp%LQL3m%l>?Y;TWG<eXes@Z`*$>0`ztySi++YoiEfGsM%?UAj#)fmH0fK2{f_5~5X>f$g0C53{b7f<2GBq}9F`)y>V@$3MNvyO1*rdj`{)|<(4G~-P0Ct?gKo2rl%`rF',
        'eb9c1ad35aac9c71': 'enr=_<guQI<5l3<MLpP%$R(Ut$~G6VBUTe_2<DP7@AynC@+0)M3P>A=|HjLA-MoVR+B&Rn&O{CUb#id6R~XaJiQj&0fK2{f_5~5X>f$bGh}0lb7f<2GBq}9F`)wOd@Tj%lD4x~phg<p>jjtP)0mE_TKMaV2tv>IW4Dk',
        '5b378d39913b1f93': 'enr-tree-link=morenodes.example.org',
    })
    tree = dnsdisc.Tree.resolve('nodes.example.org', ns)
    assert(len(tree.entries) == 4)

def test_enr_tree_big():
    enrs = [ENR().set('i', str(i).encode()).sign(testkeys[0]) for i in range(0, 500)]
    tree = dnsdisc.Tree(enrs, [], 3).sign(testkeys[2])


class DictResolver():
    def __init__(self, domain, d):
        self.d = {}
        for (k, v) in d.items():
            if k == '':
                k = domain
            else:
                k = k + '.' + domain
            self.d[k] = v

    def resolveTXT(self, name):
        if name not in self.d:
            raise dns.resolver.NXDOMAIN
        return [self.d[name]]
