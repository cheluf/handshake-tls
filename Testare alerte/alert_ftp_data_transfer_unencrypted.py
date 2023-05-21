from scapy.all import *

def send_ftp_data_transfer_unencrypted():

    ip = IP(dst="192.168.1.1")  
    tcp = TCP(sport=12345, dport=21)  
    ftp = Raw(load="STOR filename\r\n")  

    packet = ip/tcp/ftp

    send(packet)

send_ftp_data_transfer_unencrypted()
