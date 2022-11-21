import scapy.all as scapy
from scapy.layers import http

def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn= proc)



def proc(packet):
    
    if packet.haslayer(http.HTTPRequest):
        print ("[+]",packet[http.HTTPRequest].host)
        
        if packet.haslayer(scapy.Raw):
            
            req = packet[scapt.Raw].load
            print ("[+]----------------->",req)
            
            
sniffer ("wlan0")    
    