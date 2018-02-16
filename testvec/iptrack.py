# -*- coding: utf-8 -*-

import time

class IPTracker:
    """
    IPTracker predicts the external IP by listening to 'statements' of the IP made by
    other hosts. Statements are of the form "Host h says my IP is a at time t".
    The current prediction is the IP stated by the majority of external hosts within a
    time window. If there is no clear majority, the predicted IP is None.

    IPTracker can also predict whether we're behind a NAT capable of 'full cone' translation,
    i.e. whether packets sent by hosts we haven't talked to before are reaching us.

    To use IPTracker, call add_contacted whenever a packet is sent to a host and call
    add_statement when a statement is received. You can use predict_ip to read the current
    predicted IP. The time parameter passed to all methods should be greater than zero and
    monotonically increasing.
    """

    def __init__(self, window=300, contact_window=600, min_statements=50):
        self.window = window                  # statement expiry time, in seconds
        self.contact_window = contact_window  # node contact expiry, in seconds
        self.min_statements = min_statements
        self._statements = {}
        self._contacts = {}
        self._last_time = 0

    def add_statement(self, host, ip, time=time.monotonic()):
        """Adds a statement about the local IP."""
        self._check_time(time)
        self._statements[host] = (ip, time)

    def add_contacted(self, host, time=time.monotonic()):
        """States that host was just contacted by us."""
        self._check_time(time)
        self._contacts[host] = time

    def predict_ip(self, time=time.monotonic()):
        """Returns the current predicted IP."""
        self._check_time(time)
        self._gc_statements(time)
        counts = {}
        maxcount, maxip = 0, None
        # Find IP with most statements.
        for (host, s) in self._statements.items():
            ip = s[0]
            c = counts.get(ip, 0) + 1
            counts[ip] = c
            if c > maxcount and c >= self.min_statements:
                maxcount, maxip = c, ip
        return maxip

    def predict_full_cone_nat(self, time=time.monotonic()):
        """Checks if the NAT is capable of Full-Cone translation."""
        self._check_time(time)
        self._gc_statements(time)
        self._gc_contacts(time)
        return any(host not in self._contacts for host in self._statements)

    def _check_time(self, time):
        assert(time >= self._last_time)
        self.last_time = time

    def _gc_statements(self, time):
        """Removes expired statements."""
        self._statements = {
            host: s for host, s in self._statements.items() if (s[1] + self.window) > time
        }

    def _gc_contacts(self, time):
        """Removes expired contacted hosts."""
        self._contacts = {
            host: t for host, t in self._contacts.items() if (t + self.contact_window) > time
        }
