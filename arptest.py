#!/usr/bin/env python\
import argparse
import fcntl
import netaddr
from scapy.all import *

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

    parser.add_argument('-c', '--connections', help='how many connections to have at once',
                    type=int, required=False, default=50)

    args = parser.parse_args()

    # ifname = 'wlp1s0'
    ifname = args.ifname

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

        if i % args.connections == 0:
            print 'join : ' + str(i) + '/' + str(len(ips))
            for t in threads:
                t.join()
                threads.remove(t)

if __name__ == "__main__":
    main()


