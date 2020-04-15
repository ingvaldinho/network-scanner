#!/usr/bin/python3

from scapy.all import *
from scapy.layers.l2 import ARP, Ether


def scan(ip):
    # On spécifie les deux niveaux avec ethernet et l'arp
    # op 1 -> " who has "
    arppacket = Ether(dst='ff:ff:ff:ff:ff:ff')/ ARP(op=1, pdst=ip)
    #srp pour l'envoie avec réponse
    answer_list =  srp(arppacket, timeout=2,verbose=False)[0]

    final_list = []
    for el in answer_list:
        final_list.append(
            {
                'ip': el[1].psrc,
                'mac_adress': el[1].hwsrc
             }
        )

    return final_list


def print_list_scan(scan_list):
    print('Ip adress\t\t\tMac Adress\n----------------------------------------------------')
    for element in scan_list:
        print(f'{element["ip"]}\t\t {element["mac_adress"]}')

scan_list = scan('10.0.2.1/24')
print_list_scan(scan_list)
