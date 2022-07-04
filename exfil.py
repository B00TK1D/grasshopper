from scapy.all import Dot11,RadioTap,sendp,hexdump
import os,binascii


def byte_xor(ba1, ba2):
    la1, la2 = list(ba1), list(ba2)
    for i, a in enumerate(la1):
        la1[i] = a ^ la2[i % len(ba2)]
    return bytes(la1)


iface = 'wlx00198681c3d9'         #Interface name here


qos = ('\x00\x00')                              # QoS Control:      0x0000
iv = os.urandom(8)                              # CCMP IV:         (randomized)

data = byte_xor(bytes("Hello world",'utf-8'), iv)

#data = ('\x48\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64')

frame = RadioTap()/Dot11(type=2, subtype=8, FCfield="protected", addr1='ff:ff:ff:ff:ff:ff', addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')/qos/iv/data



frame.show()
print("\nHexdump of frame:")
hexdump(frame)

print("IV: ")
print(iv)

sendp(frame, iface=iface)