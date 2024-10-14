#!/usr/bin/python

import argparse
from scapy.all import DNSQR, DNSRR, UDP, IP, DNS, sniff
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class DNSSniffer:
    def __init__(self, interface):
        self.interface = interface

    def grep_DNS_queries(self, packet):
        packet_time = packet.sprintf('%sent.time%')

        try:
            if DNSQR in packet and packet.dport == 53:
                print(Fore.YELLOW + packet[DNS].summary() + '\n[' + Fore.GREEN + packet[IP].src + Style.RESET_ALL + '] -> [' + Fore.RED + packet[IP].dst + Style.RESET_ALL + '] at [' + packet_time + ']')

            elif DNSRR in packet and packet.sport == 53:
                print(Fore.CYAN + packet[DNS].summary() + '\n['+ Fore.BLUE + packet[IP].src + Style.RESET_ALL + '] -> [' + Fore.MAGENTA + packet[IP].dst + Style.RESET_ALL + '] at [' + packet_time + ']')

        except Exception as e:
            print(Fore.RED + "Error processing packet: " + str(e))

    def start_sniffing(self):
        print(Fore.GREEN + f"Sniffing on interface {self.interface} for DNS traffic...")
        sniff(iface=self.interface, filter="udp and port 53", store=0, prn=self.grep_DNS_queries)

if __name__ == "__main__":
    # Set up argparse to get the interface from the user
    parser = argparse.ArgumentParser(description="DNS Sniffer Tool to capture DNS traffic.")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on (e.g., eth0, wlan0).")
    
    # Parse the arguments
    args = parser.parse_args()

    # Create sniffer object and start sniffing
    sniffer = DNSSniffer(interface=args.interface)
    sniffer.start_sniffing()
