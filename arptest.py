#!/usr/bin/env python

import argparse
import fcntl
import threading
import netaddr
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import arping
from pythonwifi.iwlibs import Wireless
import datetime


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
    print('clearing cache: {:%Y-%b-%d %H:%M:%S}'.format(datetime.datetime.now()))
    a = subprocess.Popen(['ip', 'neigh', 'flush', 'all'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    io = a.communicate()
    if len(io[1]) == 0:
        threading.Timer(n, clear_cache_timer, [n]).start()
    else:
        print 'COULD NOT CLEAR ARP CACHE'
        print io
        sys.exit(1)


def ping(ip):
    print('time sending ping: {:%Y-%b-%d %H:%M:%S}'.format(datetime.datetime.now()))
    print 'sending ping to: ' + str(ip)
    ans, unans = sr(IP(dst=ip) / ICMP(), timeout=1, verbose=False)
    return len(ans) > 0


def ping_rnd(lst):
    ip = random.choice(lst)

    if not ping(ip):
        print 'IP DOES NOT RESPOND TO PING: ' + str(ip)
        lst.remove(ip)


def ping_rnd_timer(n, lst):
    print('thread ping going')
    if len(lst) < 1:
        print 'THE LIST IS EMPTY'
        sys.exit(1)

    else:
        ping_rnd(lst)
        mu = -1 * n * math.log(random.random())
        threading.Timer(mu, ping_rnd_timer, [n, lst]).start()


def main():
    #status.noc.stonybrook.edu
    parser = argparse.ArgumentParser(description='man on the side attack detector.')
    parser.add_argument('-i', '--ifname', help='interface to use', type=str,
                        required=False, default='wlp1s0')

    parser.add_argument('-o', '--out-file', help="file to write live ip's to",
                        type=str, required=False, default=None)

    parser.add_argument('-t', '--cache-clear-interv', help="how long to wait before clearing the ARP cache",
                        type=int, required=False, default=0)

    parser.add_argument('-m', '--mu', help="how long to wait before pinging the next random IP",
                        type=float, required=False, default=0)

    args = parser.parse_args()

    ifname = args.ifname

    mask = get_netmask(ifname)
    ip_str = get_ipaddress(ifname)

    print('mask: ' + mask)
    print('ip: ' + ip_str)

    ip = netaddr.IPNetwork(ip_str + '/' + mask)
    print(ip)

    found_ips = []

    # scan whole network for live computers
    ans, unans = arping(str(ip.network) + '/' + str(ip.prefixlen), iface=ifname)

    # record all of the live IP's
    for i in ans:
        found_ips.append(i[0][ARP].pdst)

    print 'found ' + str(len(found_ips)) + ' IPs'

    # write the IP's to a file if requested
    if args.out_file is not None:
        outfile = open(args.out_file, 'w')
        wifi = Wireless(ifname)
        outfile.write('args: ' + str(args) + '\n')
        outfile.write('essid: ' + wifi.getEssid() + '\n')
        outfile.write('mode: ' + wifi.getMode() + '\n')
        outfile.write('mask: ' + mask + '\n')
        outfile.write('ip: ' + ip_str + '\n')
        outfile.write('network: ' + str(ip.network) + '/' + str(ip.prefixlen) + '\n')

        outfile.write('\n'.join(found_ips))
        outfile.write('\n')
        outfile.close()

    # schedule the ARP cache clearing
    if args.cache_clear_interv > 0:
        clear_cache_timer(args.cache_clear_interv)

    # schedule the pinging
    if args.mu > 0:
        ping_rnd_timer(args.mu, found_ips)


if __name__ == "__main__":
    main()
