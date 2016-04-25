#!/usr/bin/env python
import argparse
import fcntl
import threading
import netaddr
import signal
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import arping
from pythonwifi.iwlibs import Wireless
import datetime

def write_arp(f, txt):
    thing = '################################### new arp diff: {:%Y-%b-%d %H:%M:%S}\n'.format(datetime.datetime.now())
    #print(thing)
    f.write(thing)
    f.write(txt)

old_result = None
old_count = 0
f = open('arp_track.txt', 'w')

while True:
    a = subprocess.Popen(['arp'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    io = a.communicate()
    if len(io[1]) != 0:
        print(io)
        sys.exit(1)

    if old_result is None:
        old_result = io[0]
        write_arp(f, io[0])

    elif old_result != io[0]:
        old_result = io[0]
        write_arp(f, io[0])
        #print('Found a difference')

    new_count = io[0].count('incomplete')
    if old_count < new_count:
        print('CLEAR: '+str(new_count)+' {:%Y-%b-%d %H:%M:%S}\n'.format(datetime.datetime.now()))

    old_count = new_count

    time.sleep(1)
