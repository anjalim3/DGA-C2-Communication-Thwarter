#! /usr/bin/env python2.7
import subprocess
from scapy.all import *
from netfilterqueue import NetfilterQueue
import pymysql
import os

THRESHOLD = 20
def modify(packet):
    pkt = IP(packet.get_payload()) #converts the raw packet to a scapy compatible string

    #modify the packet all you want here
    
    if pkt is not None:

        udp_payload = pkt["IP"]["UDP"]
        dns_data = pkt["DNS"]

        __dport = udp_payload.dport
        p = subprocess.Popen(["netstat", "-unp"], stdout=subprocess.PIPE)
        out = p.stdout.read()

        __pid = None
        __procName = None
        __response = "NXDOMAIN"
        __nxdomian_count = None

        if dns_data.rcode == 3:
            __response = "NXDOMAIN"
        if dns_data.rcode == 0:
            __response = dns_data["DNS Resource Record"].rdata


        lines = out.split("\n")
        print(lines)
        del lines[0]
        for line in list(filter(None, lines)):
            tokens = list(filter(None, line.split(" ")))
            if tokens[3].split(":")[1] == __dport:
                __pid = int(tokens[-1].split("/")[0])
                __procName = tokens[-1].split("/")[1]
                break


        print(str(__pid) + " " + __procName + " " + __response + " " + __dport)


        if __pid is not None:
            connection = pymysql.connect(host='localhost',
                                     user='root',
                                     password='',
                                     db='CS460',
                                     charset='utf8mb4',
                                     cursorclass=pymysql.cursors.DictCursor)

            if __response is not "NXDOMAIN":
                os.system("sudo iptables -A INPUT -s "+ __response +" -j DROP")
                with connection.cursor() as cursor:
                    __sql = "select count(*) as prev_nxdomain_resp_count from Process_NXDomain_Tracking where pid = " + __pid + " and is_proc_dead = 0 and  response = 'NXDOMAIN' "
                    cursor.execute(__sql)
                    result = cursor.fetchone()
                    __nxdomian_count = result['prev_nxdomain_resp_count']
                if __nxdomian_count is not None and int(__nxdomian_count) > THRESHOLD:
                    pkt = IP(dst=pkt[IP].dst, src=pkt[IP].src, ihl=pkt[IP].ihl, tos=pkt[IP].tos,
                             version=pkt[IP].version, ttl=pkt[IP].ttl, flags=pkt[IP].flags, frag=pkt[IP].frag) / UDP(
                        dport=pkt[UDP].dport, sport=pkt[UDP].sport) / DNS(id=dns_data.id, qr=dns_data.qr,
                                                                          opcode=dns_data.opcode, qdcount=1, ancount=0,
                                                                          rcode=3, qd=DNSQR(qname=dns_data[DNSQR].qname,
                                                                                            qtype=dns_data[DNSQR].qtype,
                                                                                            qclass=dns_data[
                                                                                                DNSQR].qclass))

            with connection.cursor() as cursor:
                __sql = "insert into Process_NXDomain_Tracking (pid,proc_name,response,is_proc_dead) VALUES (%d, %s, %s, %d)"
                cursor.execute(__sql, (__pid, __procName, __response, 0))
                connection.commit()

            connection.close()


    packet.set_payload(str(pkt)) # set the packet content to our modified version

    packet.accept() # accept the packet


nfqueue = NetfilterQueue()
# 1 is the iptabels rule queue number, modify is the callback function
nfqueue.bind(1, modify)

try:
    print ("[*] waiting for data")
    nfqueue.run()
except KeyboardInterrupt:
    pass

nfqueue.unbind()
