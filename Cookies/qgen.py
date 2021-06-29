#!/usr/bin/env python3

import sys
import argparse
from scapy.all import *
from random import choice, randint
from string import ascii_letters, ascii_lowercase
from time import sleep


QTYPES=["A", "AAAA", "MX", "CNAME", "NS", "TXT", "SRV", "SOA"]
TLDS=["nl", "be", "de", "fr", "net", "org", "com"]

def gen_query():
    tld = choice(TLDS)
    qtype = choice(QTYPES)
    sub = ''.join([choice(ascii_lowercase) for _ in range(randint(3,15))])
    qname = sub + ".bpf-msm." + tld
    return (qtype, qname)

def gen_queries(n):
    queries = set()
    for i in range(n):
        queries.add((gen_query()))
        #queries.add(("A", chr(65+i)+".msm.nl"))

    # make sure we have NUM_QUERIES unique queries:
    while len(queries) < n:
        print("adding additional query to get to {} unique ones".format(n))
        queries.add((gen_query()))

    return queries

def gen_packets(queries, src_ip, dst_ip, **kwargs):
    ip_hdr = IP(src=RandIP(src_ip), dst=dst_ip)

    # when directly sending out via an interface, skip l2 and use send() instead
    # of sendp() (in send_queries)
    # for some reason, including l2 and using sendp does not work, perhaps
    # because we are doing everything on one single machine?

    if "mac" in kwargs:
        print("using mac ", kwargs["mac"])
        eth_hdr = Ether(src="00:00:00:00:00:00", dst=kwargs["mac"])
        l2l3 = eth_hdr/ip_hdr
    else:
        l2l3 = ip_hdr

    num_queries = len(queries)
    pkts = []
    for (qtype, qname) in queries:

        p = l2l3/UDP(sport=RandShort(), dport=53
                )/DNS(id=RandShort(), ad=1,rd=1,qd=DNSQR(qname=qname, qtype=qtype))

        pkts.append(p)
    return pkts



def send_queries(packets, iface):
    send(packets, iface=iface, verbose=0, inter=0.0)
    print("sent {} packets out of {}".format(len(packets), iface))

def write_pcap(packets, output_fn):
    wrpcap(output_fn, packets, gz=0)
    print("wrote {} packets to {}".format(len(packets), output_fn))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-n",       help="number of packets", type=int, default=1)
    parser.add_argument("-i",       help="interface to send", type=str, default="eno1")
    parser.add_argument("-w",       help="write to .pcap file", type=str, default="")
    parser.add_argument("--src",    help="source IP address or subnet", type=str, required=True)
    parser.add_argument("--dst",    help="destination IP address", type=str, required=True)
    parser.add_argument("--mac",    help="destination MAC address", type=str, default="ff:ff:ff:ff:ff:ff")
    parser.add_argument("--inf",    help="keep on sending indefinitely", action="store_true")
    args = parser.parse_args()

    queries = gen_queries(args.n)
    if args.inf:
        print("sending indefinitely")
        while True:
            packets = gen_packets(gen_queries(args.n), args.src, args.dst)
            send_queries(packets, args.i)
    elif args.w == "":
        packets = gen_packets(queries, args.src, args.dst)
        send_queries(packets, args.i)
    else:
        packets = gen_packets(queries, args.src, args.dst, mac=args.mac)
        write_pcap(packets, args.w)


