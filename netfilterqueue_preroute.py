#! /usr/bin/env python2.7
import subprocess
from scapy.all import *
from netfilterqueue import NetfilterQueue

def modify(packet):
    pkt = IP(packet.get_payload()) #converts the raw packet to a scapy compatible string

    #modify the packet all you want here
    
    if pkt is not None:
        p = subprocess.Popen(["netstat", "-unp"], stdout=subprocess.PIPE)
        out = p.stdout.read()
        #print out
        udp_payload = pkt["IP"]["UDP"]
        dns_data = udp_payload["DNS"]
        print(pkt.show())
        #print(str(udp_payload.dport) + " - " + str(dns_data.rcode))
        #pkt["IP"]["UDP"]["DNS"].rcode = 3
        if "DNS Resource Record" in dns_data and "pragyan.org" in pkt[DNS][DNSQR].qname:
            pkt = IP(dst=pkt[IP].dst,src=pkt[IP].src,ihl=pkt[IP].ihl, tos =pkt[IP].tos, version = pkt[IP].version, ttl = pkt[IP].ttl, flags = pkt[IP].flags, frag = pkt[IP].frag)/UDP(dport=pkt[UDP].dport, sport=pkt[UDP].sport)/DNS(id=dns_data.id,qr = dns_data.qr, opcode = dns_data.opcode, qdcount = 1, ancount=0,rcode=3,qd=DNSQR(qname=dns_data[DNSQR].qname, qtype = dns_data[DNSQR].qtype, qclass = dns_data[DNSQR].qclass))
            #print (str(dns_data["DNS Resource Record"].type))
            #pkt["IP"]["UDP"]["DNS"]["DNS Resource Record"].type = 6 
            #pkt["IP"]["UDP"]["DNS"]["DNS Resource Record"].rdlen = 51
            #pkt["IP"]["UDP"]["DNS"]["DNS Resource Record"].rdata = "\x02a0\x03org\x0bafilias-nst\x04info\x00\x03noc\xc03x\x02S:\x00\x00\x07\x08\x00\x00\x03\x84\x00\t:\x80\x00\x01Q\x80"
            #print dns_data["DNS Resource Record"].show()
    
    packet.set_payload(str(pkt)) #set the packet content to our modified version

    packet.accept() #accept the packet



nfqueue = NetfilterQueue()
#1 is the iptabels rule queue number, modify is the callback function
nfqueue.bind(1, modify) 
try:
    print "[*] waiting for data"
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
