#! /usr/bin/python
#Coded By Anis Joker Dz
#Email : hackermionxx@gmail.com

import sys
from datetime import datetime
try:
        from logging import getlogger, ERROR
        getlogger('scapy.runtime').setlevel(ERROR)
        from scapy.all import *
        conf.verb = 0
except ImportError:
        print ' [!] Failed to import Scapy, Please Install it Boss[^_^]'
        sys.exit(1)

class ArpEnumerator(object):
        def __init__(self, interface=False, passive=False, range=False):
                self.interface = interface
                self.passive = passive
                self.range = range
                self.discovered_hosts = {}
                self.filter = 'arp'
                self.starttime = datetime.now()
def passive_handler(self, pkt):
        try:
                if not pkt[ARP].psrc in self.discovered_hosts.keys():
                        print "%s - %s" %(pkt[ARP].psrc, pkt[ARP].hwsrc)
                        self.discovered_hosts[pkt[ARP].psrc] = pkt[ARP].hwsrc
        except Exception:
               return
        except KeyboardInterrupt:
               return
def passive_sniffer(self):
        if not self.range:
                print '[*] No Range Given; Sniffing all ARP Traffic'
        else:
                self.filter += ' and (net %s)' %(self.range)
        print '[*] Sniffing Started on Boss %s\n' %(self.interface)
        try:
                sniff(filter=self.filter, prn=self.passive_handler, store=0)
        except Exception:
                print '\n[!] Sorry Boss An Unknown Error Occured'
                return
        print '\n [*] Sniffing Stopped Boss'
        self.duration = datetime.now() -self.starttime
        print '[*] Sniff Duration: %s' %(self.duration)
def active_scan(self):
        print '[*] Scanning for Hosts... ',
        sys.stdout.flush()
        try:
                ans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=self.range), timeout=2, iface=self.interface, inter=0.1)[0]
        except Exception:
               print '[FAIL]'
               print '[!] An Unknown Error Occutred'
               return
        print '[DONE]\n[*] Displaying Discovered Hosts:\n'
        for snd, rcv in ans:
                self.discovered_hosts[rcv[ARP].psrc] = rcv[ARP].hwsrc
                print '%s - %s' %(rcv[ARP].psrc, rcv[ARP].hwsrc)
        print '\n[*] Scan Complete Boss'
        self.duration = datatime.now() - self.starttime
        print '[*] Scan Duration: %s' %(self.duration)
        return     
def output_results(self, path):
        print '[*] Writing to Output File...',
        try:
                with open(path, 'w') as file:
                        file.write('Discovered Hosts: \n')
                        for key, val in self.discovered_hosts.items(): 
                                file.write('%s - %s\n' %(key, val))
                        file.write('\nScan Duration: %s\n' %(self.duration))
                print '[DONE]\n[*] Successfully Wrote to %s' %(path)
                return
        except IOError:
                print '\n[!] Failed to Write Output File'
                return
if __name__ == '__main__':
        import argparse
        parser = argparse.ArgumentParser(description='ARP-based Network Enumeration Tool')
        parser.add_argument('-i', '--interface', help='Network interface to scan/sniff on Master', action='store', dest='interface', default=False)
        parser.add_argument('-r', '--range' , help='Range of IPs in CIDR notation Master', action='store', dest='range', default=False) 
        parser.add_argument('--passive', help='Enable passive mode (No packets sent, sniff only Master)', action='store_true', dest='passive', default=False)
        parser.add_argument('-o', help='Output scan results to test file', action='store', dest='file', default=False)
        args = parser.parse_args()
if not args.interface:
         parser.error('No network interface given Man wth')
elif (not args.passive) and (not args.range):
       parser.error('No range sprecified for active scan damn')
else:
       pass
if args.passive:
        if not not args.range:
                enum = ArpEnumerator(interface=args.interface, passive=True, range=args.range)
                enum.passive_sniffer()
        else:
                enum = ArpEnumerator(interface=args.interface, passive=True)
                enum.passive_sniffer()
else:
        enum = ArpEnumerator(interface=args.interface, range=args.range)
        enum.active_scan()
if not not args.file:
        enum.output_results(args.file)
