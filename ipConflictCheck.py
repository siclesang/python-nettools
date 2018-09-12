#/usr/bin/env python
#coding=utf-8
'''
argv[1]	: 要检测的ip

广播50次 op=1 who-has ip 获得 mac地址进行比较
'''

from scapy.all import *
import sys

arp_frame = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1,pdst=sys.argv[1])
resp, unans = srp(arp_frame,timeout=2)
print resp[0][1].hwsrc
flag=0
for i in range(1,50):
        r,j=srp(arp_frame,timeout=2)
        print r[0][1].hwsrc
        if r[0][1].hwsrc != resp[0][1].hwsrc:
                flag=1
                print "ip 冲突，mac addresses : "+ r[0][1].hwsrc +" "+ resp[0][1].hwsrc
                break
if flag == 0 :
        print 'ip ok'
