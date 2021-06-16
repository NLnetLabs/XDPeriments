#!/usr/bin/env python3

from scapy.all import *
from random import choice, randint
from string import ascii_letters, ascii_lowercase
from time import sleep

NUM_QUERIES = 10
for i in range(NUM_QUERIES):


    sub = ''.join([choice(ascii_lowercase) for _ in range(randint(5,10))])
    qname = sub + ".fake.nl"
    qtype = choice(["A", "AAAA", "MX", "CNAME", "NS", "TXT", "SRV", "SOA"])

    p = IP(src=RandIP("192.168.99.0/24"),dst="192.168.10.21")/UDP(sport=RandShort(), dport=53
            )/DNS(id=RandShort(), ad=1,rd=1,qd=DNSQR(qname=qname, qtype=qtype))

    send(p, iface="eno1", verbose=0)
    if i % (NUM_QUERIES/10) == 0:
        print("sent {}/{}".format(i, NUM_QUERIES))

    #sleep(0.001)

