from scapy.all import get_if_list, sniff, conf
import platform
import time
from queue import Queue

captured_packets_in_memory = [] 

def log_packet_to_memory(packet):
    global captured_packets_in_memory
    captured_packets_in_memory.append(packet)

if platform.system() == "Windows":
    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        print("Warning: get_windows_if_list not found. Using generic interface names.")

from detector import check_for_attack 
from notifier import send_attack_alert 
adapter_map_global = {}

def get_packet_details(packet):
    protocol = "IP"
    sport = "N/A"
    dport = "N/A"

    if 'TCP' in packet:
        protocol = "TCP"
        sport = str(packet['TCP'].sport)
        dport = str(packet['TCP'].dport)
    elif 'UDP' in packet:
        protocol = "UDP"
        sport = str(packet['UDP'].sport)
        dport = str(packet['UDP'].dport)
    elif 'ICMP' in packet:
        protocol = "ICMP"
        sport = "N/A"
        dport = "N/A"
    elif 'Ether' in packet and not 'IP' in packet:
        protocol = "Ethernet"
    
    return protocol, sport, dport


def get_all_adapters():
    adapter_map = {}
    if platform.system() == "Windows":
        try:
            windows_if_list = get_windows_if_list()
            for interface in windows_if_list:
                display_name = f"{interface.get('name', 'N/A')} ({interface.get('description', 'Adapter')})"
                sniffing_name = interface.get('name', interface.get('description')) 
                if sniffing_name:
                    adapter_map[display_name] = sniffing_name
                    
        except Exception as e:
            print(f"Windows specific adapter retrieval failed: {e}. Falling back to generic list.")

    if not adapter_map:
        try:
            for dev_name, iface_obj in conf.ifaces.items():
                display_name = iface_obj.description if iface_obj.description else dev_name
                adapter_map[display_name] = dev_name
        except Exception:
            for name in get_if_list():
                 adapter_map[name] = name
                 
    global adapter_map_global
    adapter_map_global = adapter_map
    return adapter_map

def process_packet(packet, packet_queue: Queue, intended_email):
    
    log_packet_to_memory(packet)
    
    src_ip = packet['IP'].src if 'IP' in packet else "N/A"
    dst_ip = packet['IP'].dst if 'IP' in packet else "N/A"

    if src_ip=="0.0.0.0": # Replace with actual source IP
        return

    if 'IP' in packet:
        attack_type = check_for_attack(packet) 
    else:
        attack_type = None
    
    if attack_type:
        alert_timestamp = time.strftime('%H:%M:%S')
        log_message = (
            f"[{alert_timestamp}] ALERT: {attack_type} "
            f"from {src_ip} targeting {dst_ip}\n"
        )
        packet_queue.put(('ALERT', log_message)) 

        send_attack_alert(intended_email, attack_type, src_ip, dst_ip)


def start_capture_thread(adapter_name, stop_event, packet_queue, intended_email, bpf_filter_string="ip"):
    sniffing_iface = adapter_map_global.get(adapter_name, adapter_name)
    print(f"Starting capture on interface: {sniffing_iface} with filter: {bpf_filter_string}")
    
    try:
        sniff(
            iface=sniffing_iface, 
            prn=lambda p: process_packet(p, packet_queue, intended_email), 
            stop_filter=lambda p: stop_event.is_set(),
            store=False, 
            filter=bpf_filter_string
        )
        print(f"Sniffer thread stopped normally on {sniffing_iface}.")
        
    except Exception as e:
        print(f"FATAL Sniffing error on {sniffing_iface}: {e}. Check permissions (Run as Admin) or adapter name.")

def stop_capture(stop_event):
    stop_event.set()
    print("Signal sent to stop sniffer thread.")