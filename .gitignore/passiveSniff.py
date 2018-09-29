''' Document including the Passive sniffing and packet monitoring using Scapy
    package.
'''

from scapy.all import *
from os import system as sys

sys('clear')

def sniffer(pkt):
    pkt.show()
 
def sniffer_arp(pkt):
    if pkt[ARP].op == 1: #who-has (request)
        return 'Request: {} is asking about {}'.format(pkt[ARP].psrc, pkt[ARP].pdst)
    if pkt[ARP].op == 2: #is-at (response)
        return '*Response: {} has address {}'.format(pkt[ARP].hwsrc, pkt[ARP].psrc)

def sniffer_http(pkt):
    print("Source IP: {} <--HTTP--> Dest IP: {} Dest Port: {}  Payload:{}".format(pkt[IP].src,pkt[IP].dst,pkt[TCP].dport,str(bytes(pkt[TCP].payload))))

def sniffer_mac(pkt):
    print("Source MAC:{}<-----> Dest MAC:{}".format(pkt[Ether].src,pkt[Ether].dst))


def sniffer_ip(pkt):
    print("Source IP:{} <-----> Dest IP: {}".format(pkt[IP].src,pkt[IP].dst))

pkt = IP()/TCP()/Ether()

print "---PACKET DETAILS---\n"
sniffer(pkt)
sniffer_ip(pkt)
sniffer_mac(pkt)
sniffer_http(pkt)



''' -
-----------------OUTPUT OF THE FOLLOWING-------------
---PACKET DETAILS---

###[ IP ]### 
  version   = 4
  ihl       = None
  tos       = 0x0
  len       = None
  id        = 1
  flags     = 
  frag      = 0
  ttl       = 64
  proto     = tcp
  chksum    = None
  src       = 127.0.0.1
  dst       = 127.0.0.1
  \options   \
###[ TCP ]### 
     sport     = ftp_data
     dport     = http
     seq       = 0
     ack       = 0
     dataofs   = None
     reserved  = 0
     flags     = S
     window    = 8192
     chksum    = None
     urgptr    = 0
     options   = {}
###[ Ethernet ]### 
        dst       = ff:ff:ff:ff:ff:ff
        src       = 08:00:27:2a:48:67
        type      = 0x9000

Source IP:127.0.0.1 <-----> Dest IP: 127.0.0.1
Source MAC:08:00:27:2a:48:67<-----> Dest MAC:ff:ff:ff:ff:ff:ff
Source IP: 127.0.0.1 <--HTTP--> Dest IP: 127.0.0.1 Dest Port: 80  Payload:����'*Hg�
'''