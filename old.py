from scapy.all import Dot11,RadioTap,sendp,hexdump

iface = 'wlx00198681c3d9'         #Interface name here

dot11 = (
    '\x88'                                  # Type: QoS Data
    '\x41'                                  # Flags: Frame from STA to a DS via AP + protected
    '\x2c\x00'                              # Duration 44ms
    '\x6c\xaa\xb3\xc5\xa1\x08'              # Receiver MAC:     6c:aa:b3:c5:a1:08
    '\x04\xed\x33\x2e\x7a\xbb'              # Transmitter MAC:  04:ed:33:2e:7a:bb
    '\x01\x00\x5e\x7f\xff\xfa'              # Destination MAC:  01:00:5e:7f:ff:fa
    '\xa0\x2a'                              # Sequence number:  682, fragment number 0
    '\x00\x00'                              # QoS Control:      0x0000
    '\x1e\x36\x00\x20\x00\x00\x00\x00'      # CCMP IV:         1e36002000000000
)



header = (
    '\x60\x98\x00\x00\x0c\x1a\x00\x20\x00\x00\x00\x00'
)

data = ('\x48\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64')


# create new radiotap frame with raw data
frame = RadioTap()/Dot11(type=2, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')/header/data

#frame = RadioTap()/dot11/data


frame.show()
print("\nHexdump of frame:")
hexdump(frame)
#raw_input("\nPress enter to start\n")

sendp(frame, iface=iface)