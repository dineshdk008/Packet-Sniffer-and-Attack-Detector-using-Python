from scapy.all import IP, TCP, ICMP
from collections import defaultdict
import time

SYN_FLOOD_THRESHOLD = 50 
PING_FLOOD_THRESHOLD = 20
DETECTION_WINDOW = 20 

traffic_state = defaultdict(lambda: {'syn_count': 0, 'ping_count': 0, 'last_time': time.time()})

def check_for_attack(packet):
    if not packet.haslayer(IP):
        return None
    
    src_ip = packet[IP].src
    key = src_ip
    current_time = time.time()

    if current_time - traffic_state[key]['last_time'] > DETECTION_WINDOW:
        traffic_state[key]['syn_count'] = 0
        traffic_state[key]['ping_count'] = 0
    
    traffic_state[key]['last_time'] = current_time

    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        traffic_state[key]['syn_count'] += 1
        
        if traffic_state[key]['syn_count'] > SYN_FLOOD_THRESHOLD:
            return "SYN Flood"
            
    elif packet.haslayer(ICMP):
        traffic_state[key]['ping_count'] += 1
        
        if traffic_state[key]['ping_count'] > PING_FLOOD_THRESHOLD:
            return "ICMP Ping Flood"
        
    return None