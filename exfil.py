from time import sleep
from scapy.all import Dot11,RadioTap,sendp,hexdump
import os,binascii

import fcntl
import socket
import struct


def byte_xor(ba1, ba2):
    la1, la2 = list(ba1), list(ba2)
    for i, a in enumerate(la1):
        la1[i] = a ^ la2[i % len(ba2)]
    return bytes(la1)


def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])


def setMonitorMode(ifname):
    os.system("ifconfig " + ifname + " down")
    os.system("iwconfig " + ifname + " mode monitor")
    os.system("ifconfig " + ifname + " up")

def unsetMonitorMode(ifname):
    os.system("ifconfig " + ifname + " down")
    os.system("iwconfig " + ifname + " mode managed")
    os.system("ifconfig " + ifname + " up")


def getFrame(msg):
    qos = ('\x00\x00')                              # QoS Control:      0x0000
    iv = os.urandom(8)                              # CCMP IV:         (randomized)
    data = byte_xor(bytes(msg,'utf-8'), iv)
    #data = bytes(msg,'utf-8')
    frame = RadioTap()/Dot11(type=2, subtype=8, FCfield="protected")/qos/iv/data
    return frame



#iface = 'wlx00198681c3d9'         #Interface name here




#frame.show()
#print("\nHexdump of frame:")
#hexdump(frame)


device = input("Enter wireless interface name: ")
line = '1'

setMonitorMode(device)
print("Enter message below, or blank line to exit:")
while line != '':
    line = input()
    frame = getFrame(line)
    sendp(frame, device)
    sleep(.1)
unsetMonitorMode(device)