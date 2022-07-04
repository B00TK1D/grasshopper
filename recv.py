#!/usr/bin/env python

from scapy.all import Dot11, sniff
import binascii
                       

def byte_xor(ba1, ba2):
    la1, la2 = list(ba1), list(ba2)
    for i, a in enumerate(la1):
        la1[i] = a ^ la2[i % len(ba2)]
    return bytes(la1)

def PacketHandler(packet):
    if packet.haslayer(Dot11):
        if packet.type == 2 and packet.subtype == 8:
            #print(packet.addr2)
            if packet.addr2 == '22:22:22:22:22:22' and len(list(bytes(packet))) > 53:
                iv = bytes(list(bytes(packet))[39:47])
                data = bytes(list(bytes(packet))[47:])
                data = byte_xor(data, iv)
                #print(data.decode('utf-8'))
                # Decrypt WEP data
                print(data)
                #print(iv)


sniff(iface="wlx00198681c3d9", prn = PacketHandler)
#print(byte_xor(b"Hello world", b"\x03\x01").decode('utf-8'))