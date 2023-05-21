from scapy.all import *


ip = IP(dst="192.168.1.1")  
tcp = TCP(sport=12345, dport=21)  
ftp = Raw(load="PASS password\r\n")  

packet = ip/tcp/ftp

send(packet)
