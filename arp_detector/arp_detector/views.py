from django.shortcuts import render
import scapy.all
from scapy.layers.inet import *
from scapy.sendrecv import sniff
from scapy.layers.l2 import ARP, Ether


def home(request):

    sniff_('Wi-Fi 3')

    return render(request, 'home.html')


def get_mac_address(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.str(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def sniff_(interface):
    sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet[ARP].op == 2 and packet.haslayer(scapy.layers.l2.ARP):
        real_mac = get_mac_address(packet[scapy.layers.l2.ARP].psrc)
        resp_mac = packet[scapy.layers.l2.ARP].hwsrc

        if real_mac != resp_mac:
            print('You are under attack!')
        else:
            print('Everything seems to be ok...')
