# -*- coding: utf-8 -*-

from .iptrack import *

# Check that it doesn't crash if there are no statements.
def test_iptrack_empty():
    t = IPTracker(min_statements = 0)
    assert(t.predict_ip(time = 0) is None)

# Check that min_statements works.
def test_iptrack_min_statements():
    t = IPTracker(min_statements = 3)
    t.add_statement('host_1', '127.0.0.1', time = 1)
    assert(t.predict_ip(time = 1) is None)
    t.add_statement('host_2', '127.0.0.1', time = 2)
    assert(t.predict_ip(time = 2) is None)
    t.add_statement('host_3', '127.0.0.1', time = 3)
    assert(t.predict_ip(time = 3) is '127.0.0.1')

# # This should return None because there is no clear winner.
# # Not sure if this feature is needed.
# def test_iptrack_tie():
#     t = IPTracker(min_statements = 1)
#     t.statement('host_1', '127.0.0.1', time = 1)
#     t.statement('host_2', '127.0.0.1', time = 2)
#     assert(t.ip(time = 3) is None)

# Checks that statements expire.
def test_iptrack_expire():
    t = IPTracker(window = 30, min_statements = 2)
    t.add_statement('host_1', '127.0.0.1', time = 1)
    t.add_statement('host_2', '127.0.0.1', time = 1)
    t.add_statement('host_3', '127.0.0.1', time = 1)
    assert(t.predict_ip(time = 2) is '127.0.0.1')
    assert(t.predict_ip(time = 32) is None)

# Checks that predict_full_cone works.
def test_iptrack_fullcone():
    t = IPTracker(window = 10, contact_window = 30)
    t.add_contacted('host_1', time = 1)
    t.add_statement('host_1', '127.0.0.1', time = 2)
    assert(t.predict_full_cone_nat(time = 3) is False)
    t.add_statement('host_2', '127.0.0.1', time = 4)
    assert(t.predict_full_cone_nat(time = 5) is True)
    # expiration:
    assert(t.predict_full_cone_nat(time = 50) is False)
