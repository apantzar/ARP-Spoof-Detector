from django.shortcuts import render
import scapy.all

from scapy.layers.inet import *
from get_nic import getnic


def home(request):
    sniff("wlan0")

    return render(request, 'home.html')


def get_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.str(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet[scapy.ARP].op == 2 and packet.haslayer(scapy.ARP):
        real_mac = get_mac_address(packet[scapy.ARP].psrc)
        resp_mac = packet[scapy.ARP].hwsrc

        if real_mac != resp_mac:
            print('You are under attack!')
        else:
            print('Everything seems to be ok...')
