from scapy.all import sniff, IP, TCP

def print_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        print("Source IP: ", packet[IP].src)
        print("Destination IP: ", packet[IP].dst)
        print("Source Port: ", packet[TCP].sport)
        print("Destination Port: ", packet[TCP].dport)
        print("Payload: ", packet[TCP].payload)
        print("---")

sniff(filter="tcp", prn=print_packet)