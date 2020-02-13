#!/usr/bin/env python
import sys
import struct
import os
import argparse
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, TCP, Ether
from scapy.layers.inet import _IPOption_HDR
from scapy.fields import *
from scapy.all import load_contrib

load_contrib('nsh')

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def handle_pkt(pkt, iface):
    print "got a packet"
    # TODO decrease SI in NSH header and forward the packet back to switch
    # import ipdb;ipdb.set_trace()
    
    try:
        pkt.show2()
        pkt.si = pkt.si - 1
        pkt.dst = 'ff:ff:ff:ff:ff:ff'
        print "Forward packet"
        pkt.show2()
        sendp(pkt, iface=iface, verbose=True)
        sys.stdout.flush()
    except AttributeError:
        print "Error "



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--if2", help="host-eth", default='h1-eth0')
    args = parser.parse_args()
    
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    #iface = ifaces[0]
    #iface = 's2-eth2'
    iface=args.if2
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x, iface))

if __name__ == '__main__':
    main()