#!/usr/bin/python

import threading

from scapy.layers.l2 import arping
from scapy.all import *


class Arpthread (threading.Thread):
    def __init__(self, ip):
        threading.Thread.__init__(self)
        self.ip = ip
        self.found_ip = None

    def run(self):
        ans, unans = arping(str(self.ip), verbose=False, timeout=2)
        if ans is not None and len(ans) > 0:
            ans.show()
            self.found_ip = ans.res[0][0][ARP].pdst
