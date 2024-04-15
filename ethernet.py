from scapy.all import Ether, IP, TCP, ICMP, sniff #I used WinPcap and Npcap, these libraries let me take advatage of scapy on a windows machine that I am using
#I wouldn't need to use WinPcap if i was in a linux or unix based machine or VM

def packet_handler(packet):
     print('\nEthernet Frame:')   
     if Ether in packet:
        dest_mac = packet[Ether].dst  #Ether uses the Npcap library to get the destination address
        src_mac = packet[Ether].src #Ether uses the Npcap library to get the source destination 
        eth_proto = packet[Ether].type #Ether uses the Npcap library to get the protocol typle

        print('\n MAC Information')
        print('Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto)) #Displays the MAC address in a correct format
    
     if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        ip_proto = packet[IP].proto
        ip_len = packet[IP].len

        print('\nIP Header information')
        print('Source IP: {}, Destination IP: {}'.format(ip_src, ip_dst))
        print('Protocol: {}, Length: {}'.format(ip_proto, ip_len))

        if ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code

            print('\nICMP Packet information')
            print('Type: {}, Code: {}'.format(icmp_type, icmp_code))

        if TCP in packet:
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            tcp_flags = packet[TCP].flags

            print('\nTCP Packet information')
            print('Source Port: {}, Destination Port: {}'.format(tcp_src_port, tcp_dst_port))
            print('Flags: {}'.format(tcp_flags))


def main():
    print("Press enter to stop the information...")
    sniff(prn=packet_handler, filter="ether or ip or icmp or tcp", store=0)
    input("Press ENTER to exit...")
if __name__ == "__main__":
    main()  