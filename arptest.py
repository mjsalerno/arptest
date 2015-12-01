#!/usr/bin/env python
import argparse
import fcntl
import threading
import subprocess
from operator import sub

import netaddr
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import arping


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


def clear_cache_timer(n):
    print 'clearing ARP cache'
    a = subprocess.Popen(['ip', 'neigh', 'flush', 'all'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    io = a.communicate()
    if len(io[1]) == 0:
        threading.Timer(n, clear_cache_timer, [n]).start()
    else:
        print 'COULD NOT CLEAR ARP CACHE'
        print io
        sys.exit(1)


def ping(ip):
    print 'sending ping to: ' + str(ip)
    ans, unans = sr(IP(dst=ip)/ICMP(), timeout=1, verbose=False)
    return len(ans) > 0


def ping_rnd(lst):
    ip = random.choice(lst)

    if not ping(ip):
        print 'IP DOES NOT RESPOND TO PING: ' + str(ip)
        lst.remove(ip)


def ping_rnd_timer(n, lst):
    if len(lst) < 1:
        print 'THE LIST IS EMPTY'
        sys.exit(1)

    else:
        ping_rnd(lst)
        threading.Timer(n, ping_rnd_timer, [n, lst]).start()


def main():

    parser = argparse.ArgumentParser(description='man on the side attack detector.')
    parser.add_argument('-i', '--ifname', help='interface to use', type=str,
                    required=False, default='wlp1s0')

    parser.add_argument('-o', '--out-file', help="file to write live ip's to",
                    type=str, required=False, default='live-ips.txt')

    parser.add_argument('-t', '--cache-clear-interv', help="how long to wait before clearing the ARP cache",
                    type=int, required=False, default=0)

    parser.add_argument('-p', '--ping-interv', help="how long to wait before pinging the next random IP",
                    type=int, required=False, default=0)

    args = parser.parse_args()

    ifname = args.ifname

    mask = get_netmask(ifname)
    ip = get_ipaddress(ifname)

    print('mask: ' + mask)
    print('ip: ' + ip)

    ip = netaddr.IPNetwork(ip + '/' + mask)
    print(ip)

    found_ips = []
    outfile = open(args.out_file, 'w')

    ans, unans = arping(str(ip.network) + '/' + str(ip.prefixlen))

    for i in ans:
        found_ips.append(i[0][ARP].pdst)

    print 'found ' + str(len(found_ips)) + ' IPs'
    outfile.write('\n'.join(found_ips))
    outfile.close()

    if args.cache_clear_interv > 0:
        clear_cache_timer(args.cache_clear_interv)

    if args.ping_interv > 0:
        ping_rnd_timer(args.ping_interv, found_ips)

if __name__ == "__main__":
    main()


