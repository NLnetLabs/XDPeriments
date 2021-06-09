#!/usr/bin/env python3

from scapy.all import *
from random import choice, randint
from string import ascii_letters
from time import sleep

sources = IP(src="127.0.0.0/24", dst="127.0.0.1")/UDP(sport=RandShort(), dport=53)
qnames = [''.join([random.choice(ascii_letters) for _ in
    range(randint(1,20))])+".fake.nl" for _ in range(2)]

NUM_QUERIES = 100
for i in range(NUM_QUERIES):


    sub = ''.join([choice(ascii_letters) for _ in range(randint(1,63))])
    qname = sub + ".fake.nl"
    qtype = choice(["A", "AAAA", "MX", "CNAME", "NS", "TXT", "SRV", "SOA"])

    p = IP(src=RandIP("127.0.0.0/16"), dst="127.0.0.1")/UDP(sport=RandShort(),
            dport=53)/DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    send(p, iface="lo", verbose=0)
    if i % 10 == 0:
        print("sent {}/{}".format(i, NUM_QUERIES))

    sleep(0.01)

