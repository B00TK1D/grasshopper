from scapy.all import Dot11,RadioTap,sendp,hexdump
import os,binascii

iface = 'wlx00198681c3d9'         #Interface name here




# 0000  00 00 08 00 00 00 00 00 88 00 00 00 FF FF FF FF  ................
# 0010  FF FF 22 22 22 22 22 22 33 33 33 33 33 33 00 00  ..""""""333333..
# 0020  60 C2 98 00 00 0C 1A 00 20 00 00 00 00 48 65 6C  `....... ....Hel
# 0030  6C 6F 20 77 6F 72 6C 64                          lo world

# 0000  00 00 08 00 00 00 00 00 C2 88 42 2C 00 11 11 11  ..........B,....
# 0010  11 11 11 22 22 22 22 22 22 33 33 33 33 33 33 C2  ...""""""333333.
# 0020  A0 2A 00 00 00 00 00 00 00 00 00 00 48 65 6C 6C  .*..........Hell
# 0030  6F 20 77 6F 72 6C 64                             o world

radiotap = (
    '\x00\x00\x08\x00\x00\x00\x00\x00'
)

dot11 = (
    '\x88'                                  # Type: QoS Data
    '\x42'                                  # Flags: Frame from STA to a DS via AP + protected
    '\x2c\x00'                              # Duration 44ms
    #'\x6c\xaa\xb3\xc5\xa1\x08'              # Receiver MAC:     6c:aa:b3:c5:a1:08
    #'\x00\x19\x86\x81\xc3\xd9'              # Transmitter MAC:  00:19:86:81:c3:d9
    #'\x01\x00\x5e\x7f\xff\xfa'              # Destination MAC:  01:00:5e:7f:ff:fa
    '\x11\x11\x11\x11\x11\x11'              # Receiver MAC:     ff:ff:ff:ff:ff:ff
    '\x22\x22\x22\x22\x22\x22'              # Transmitter MAC:  22:22:22:22:22:22
    '\x33\x33\x33\x33\x33\x33'              # Destination MAC:  33:33:33:33:33:33
    '\xa0\x2a'                              # Sequence number:  682, fragment number 0
    '\x00\x00'                              # QoS Control:      0x0000
    #'\x1e\x36\x00\x20\x00\x00\x00\x00'      # CCMP IV:         1e36002000000000
    '\x00\x00\x00\x00\x00\x00\x00\x00'      # CCMP IV:         1e36002000000000
)

qos = ('\x00\x00')                              # QoS Control:      0x0000

iv = os.urandom(8)                          # CCMP IV:         (randomized)

data = ('\x48\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64')


# create new radiotap frame with raw data
#frame = RadioTap()/Dot11(type=2, subtype=8, FCfield=2, addr1='ff:ff:ff:ff:ff:ff',
#addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')/data
#frame = RadioTap()/Dot11(type=2, subtype=8, FCfield="protected", addr1='ff:ff:ff:ff:ff:ff',
#addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')/Dot11Encrypted()/data
frame = RadioTap()/Dot11(type=2, subtype=8, FCfield="protected", addr1='ff:ff:ff:ff:ff:ff',
addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')/data

#frame = RadioTap()/dot11/data
#frame=RadioTap()


frame.show()
print("\nHexdump of frame:")
hexdump(frame)
#raw_input("\nPress enter to start\n")

sendp(frame, iface=iface, inter=0.100, loop=5)