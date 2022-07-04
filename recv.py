#!/usr/bin/env python

from scapy.all import Dot11, sniff
import binascii
import os
                       

def byte_xor(ba1, ba2):
    la1, la2 = list(ba1), list(ba2)
    for i, a in enumerate(la1):
        la1[i] = a ^ la2[i % len(ba2)]
    return bytes(la1)

def setMonitorMode(ifname):
    os.system("ifconfig " + ifname + " down")
    os.system("iwconfig " + ifname + " mode monitor")
    os.system("ifconfig " + ifname + " up")

def unsetMonitorMode(ifname):
    os.system("ifconfig " + ifname + " down")
    os.system("iwconfig " + ifname + " mode managed")
    os.system("ifconfig " + ifname + " up")


def PacketHandler(packet):
    if packet.haslayer(Dot11):
        if packet.type == 2 and packet.subtype == 8:
            #print(packet.addr2)
            if packet.addr2 == '00:00:00:00:00:00':
                iv = bytes(list(bytes(packet))[39:47])
                data = bytes(list(bytes(packet))[47:])
                data = byte_xor(data, iv)
                #print(data.decode('utf-8'))
                # Decrypt WEP data
                if data != b'' and (not 0 in list(data)):
                    print(data.decode('utf-8'))
                #print(iv)



device = input("Enter wireless interface name: ")

setMonitorMode(device)
sniff(iface="wlx00198681c3d9", prn = PacketHandler)
