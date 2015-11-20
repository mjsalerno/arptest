import socket
import fcntl
import struct
import netaddr
from scapy.layers.l2 import arping
from scapy.all import *
import threading

from arpthread import Arpthread


def get_netmask(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891b, struct.pack('256s', ifname))[20:24])


def get_ipaddress(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


ifname = 'wlp1s0'

mask = get_netmask(ifname)
ip = get_ipaddress(ifname)

print('mask: ' + mask)
print('ip: ' + ip)

ip = netaddr.IPNetwork(ip + '/' + mask)
print(ip)

threads = []
ips = list(ip)

for i in range(len(ips)):
    addy = str(ips[i])
    t = Arpthread(addy)
    t.start()
    threads.append(t)

    if i % 50 == 0:
        print 'join : ' + str(i) + '/' + str(len(ips))
        for t in threads:
            t.join()
            threads.remove(t)


