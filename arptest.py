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

count = 0


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
    while True:
        print('clearing cache: {:%Y-%b-%d %H:%M:%S}'.format(datetime.datetime.now()))
        a = subprocess.Popen(['ip', 'neigh', 'flush', 'all'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        io = a.communicate()
        if len(io[1]) != 0:
            print(io)
            sys.exit(1)
        time.sleep(n)


def ping(ip):
    print('time sending ping: {:%Y-%b-%d %H:%M:%S}'.format(datetime.datetime.now()))
    print('sending ping to: ' + str(ip))
    ans, unans = sr(IP(dst=ip) / ICMP(), timeout=1, verbose=False)
    return len(ans) > 0


def ping_rnd(a, b):
    global ip_lst
    global ip_index
    if len(ip_lst) == 0:
        print('THE LIST IS EMPTY.')
        sys.exit(1)

    ip = ip_lst[ip_index]
    if not ping(ip):
        print('IP DOES NOT RESPOND TO PING: ' + str(ip))
        del ip_lst[ip_index]
    else:
        ip_index += 1
        if ip_index > (len(ip_lst) - 1):
            ip_index = 0


ip_lst = []
ip_index = 0


def main():
    global ip_lst
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

    print('found ' + str(len(found_ips)) + ' IPs')

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
        t = threading.Thread(target=clear_cache_timer, args=[args.cache_clear_interv])
        t.start()

    # schedule the pinging
    if args.mu <= 0:
        sys.exit(1)

    ip_lst = found_ips
    signal.signal(signal.SIGALRM, ping_rnd)
    signal.setitimer(signal.ITIMER_REAL, args.mu, args.mu)

    while True:
        signal.pause()


    #while(True):
    #t = threading.Thread(target=ping_timer, args=[args.mu, found_ips])
    #t.start()
    #t.join()
    #print('successful pings: ' + count)
        #mu = -1 * args.mu * math.log(random.random())
        #thr = threading.Timer(mu, ping_rnd, [found_ips])
        #thr.start()
        #print('ELLEN: ', threading.activeCount())
        #thr.join()


if __name__ == "__main__":
    main()
