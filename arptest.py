#!/usr/bin/env python
import argparse
import fcntl
import netaddr
from scapy.all import *
from scapy.layers.l2 import arping

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


def main():

    parser = argparse.ArgumentParser(description='man on the side attack detector.')
    parser.add_argument('-i', '--ifname', help='interface to use', type=str,
                    required=False, default='wlp1s0')

    parser.add_argument('-o', '--out-file', help="file to write live ip's to",
                    type=str, required=False, default='live-ips.txt')

    args = parser.parse_args()

    ifname = args.ifname

    mask = get_netmask(ifname)
    ip = get_ipaddress(ifname)

    print('mask: ' + mask)
    print('ip: ' + ip)

    ip = netaddr.IPNetwork(ip + '/' + mask)
    print(ip)

    found_ips = []
    arp_cache = {}
    outfile = open(args.out_file, 'w')

    ans, unans = arping(str(ip.network) + '/' + str(ip.prefixlen))

    for i in ans:
        found_ips.append(i[0][ARP].pdst)
        arp_cache[i[0][ARP].pdst] = i[1][ARP].hwsrc

    print 'found ' + str(len(found_ips)) + ' IPs'
    outfile.write('\n'.join(found_ips))
    outfile.close()

    print arp_cache

if __name__ == "__main__":
    main()


