import tkinter as tk
from tkinter import messagebox
import webbrowser
import threading
import time
import os
import queue
from sniffer_core import (
    get_all_adapters, 
    start_capture_thread, 
    stop_capture, 
    get_packet_details,
    captured_packets_in_memory,
)
from security import authenticate_action 
log_data = []
selected_adapter = None  
adapter_name_map = {}    
stop_event = threading.Event() 
packet_queue = queue.Queue()
PROTOCOL_FILTERS = {
    "All (IP Traffic)": "ip",
    "TCP Port 80 (HTTP)": "tcp port 80",
    "TCP Port 443 (HTTPS)": "tcp port 443",
    "UDP": "udp",
    "ICMP (Control)": "icmp"
}


def log_action(action_name, details=""):
    global log_data
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    if "Authentication" not in action_name:
        log_entry = f"[{timestamp}] ACTION: {action_name} | Details: {details}"
    else:
        log_entry = f"[{timestamp}] ACTION: {action_name}"
    log_data.append(log_entry)
    print(f"LOGGED: {log_entry}") 


def check_packet_queue():
    try:
        while True:
            item = packet_queue.get_nowait()
            if isinstance(item, tuple):
                log_message = item[1]
                attack_text.insert(tk.END, log_message)
                attack_text.see(tk.END)
    except queue.Empty: 
        pass 
    except Exception as e:
        print(f"Error processing item from queue: {e}")

    root.after(100, check_packet_queue)


def start_capture_action():
    global selected_adapter
    captured_packets_in_memory.clear() 
    
    display_name = adapter_var.get()
    if display_name == "Select Adapter":
        messagebox.showerror("Error", "Please select a network adapter first.")
        return
    
    sniffing_name = adapter_name_map.get(display_name)
    if not sniffing_name:
        messagebox.showerror("Error", "Selected adapter could not be mapped to a sniffing interface. Restart the app.")
        return
        
    selected_adapter = sniffing_name
    intended_email = "abcd@gmail.com" # Replace with actual receiver email 

    if not intended_email or "@" not in intended_email:
        messagebox.showerror("Error", "Please enter a valid intended email address for alerts/passwords.")
        return

    selected_protocol_name = protocol_var.get()
    bpf_filter_string = PROTOCOL_FILTERS.get(selected_protocol_name, "ip") 
    
    if not authenticate_action("Start Capture", intended_email, log_action): 
        return
    
    log_action("Start Capture", f"{display_name} with filter: {bpf_filter_string}") 
    
    stop_event.clear()
    status_label.config(text=f"Status: Capturing packets on {display_name}...")
    start_capture_button.config(state=tk.DISABLED)
    stop_capture_button.config(state=tk.NORMAL)

    threading.Thread(
        target=start_capture_thread, 
        args=(sniffing_name, stop_event, packet_queue, intended_email, bpf_filter_string),
        daemon=True
    ).start()


def stop_capture_action():
    log_action("Stop Capture", selected_adapter if selected_adapter else "Unknown Adapter")
    stop_capture(stop_event)
    status_label.config(text="Status: Stopped.")
    start_capture_button.config(state=tk.NORMAL)
    stop_capture_button.config(state=tk.DISABLED)
    
    
def show_logs():
    intended_email = "abcd@gmail.com" # Replace with actual receiver email 

    if not intended_email or "@" not in intended_email:
        messagebox.showerror("Error", "Please enter the intended email address.")
        return

    if not authenticate_action("Show Logs", intended_email, log_action):
        return

    log_window = tk.Toplevel(root)
    log_window.title("Action Logs (In Memory)")
    log_text = tk.Text(log_window, wrap=tk.WORD, width=80, height=30)
    log_text.pack(padx=10, pady=10)
    
    if not log_data:
        log_text.insert(tk.END, "No action logs stored in memory yet.")
    else:
        log_text.insert(tk.END, "\n".join(log_data))

    log_text.config(state=tk.DISABLED) 


def show_captured_data():
    intended_email = "abcd@gmail.com" # Replace with actual receiver email 

    if not intended_email or "@" not in intended_email:
        messagebox.showerror("Error", "Please enter the intended email address.")
        return
    
    if not authenticate_action("Show Captured Data", intended_email, log_action):
        return
        
    data_window = tk.Toplevel(root)
    data_window.title("Captured Packets (In Memory)")
    data_text = tk.Text(data_window, wrap=tk.WORD, width=100, height=40)
    data_text.pack(padx=10, pady=10)

    if not captured_packets_in_memory:
        data_text.insert(tk.END, "No packets captured in memory yet. Start capture first.")
    else:
        for packet in captured_packets_in_memory:
            capture_time = time.strftime(
                '%Y-%m-%d %H:%M:%S', 
                time.localtime(float(packet.time))
            )
            protocol, sport, dport = get_packet_details(packet) 
            log_line = (
                f"[{capture_time}] Source IP: {packet['IP'].src if 'IP' in packet else 'N/A'} Source Port: {sport} "
                f"Destination IP: {packet['IP'].dst if 'IP' in packet else 'N/A'} Destination Port: {dport} " 
                f"Protocol: {protocol}\n"
            )

            data_text.insert(
                tk.END, 
                f"{log_line}\n\n{'-'*50}\n\n"
            )
            
    data_text.config(state=tk.DISABLED) 


def open_project_info():
    html_file = "project_info.html"
    if not os.path.exists(html_file):
        with open(html_file, "w") as f:
            f.write("<html><head><title>Project Info</title></head><body>"
                    "<h1>Python Network Packet Sniffer & Detector</h1>"
                    "<p>This tool was created to capture network packets, "
                    "detect network attacks (like ARP Spoofing/DoS), and send email alerts.</p>"
                    "<p>It uses Scapy for packet capture and Tkinter for the user interface.</p>"
                    "</body></html>")
    try:
        webbrowser.open_new_tab(html_file)
        log_action("Project Info", "Opened HTML file.")
    except Exception as e:
        messagebox.showerror("Error", f"Could not open HTML file: {e}")

#Start
root = tk.Tk()
root.title("Python Network Packet Sniffer & Detector")

header_frame = tk.Frame(root, padx=10, pady=10)
header_frame.pack(fill='x')

info_button = tk.Button(header_frame, text="Project Info", command=open_project_info)
info_button.pack(side=tk.TOP)

control_frame = tk.Frame(root, padx=10, pady=10, bd=2, relief=tk.GROOVE)
control_frame.pack(fill='x')

adapter_label = tk.Label(control_frame, text="Select Adapter:")
adapter_label.pack(side=tk.LEFT, padx=(0, 5))

try:
    adapter_name_map = get_all_adapters()
    adapter_options = ["Select Adapter"] + sorted(list(adapter_name_map.keys()))
except Exception as e:
    adapter_options = ["Select Adapter", f"Error: {e}"]
    print(f"Error retrieving adapters: {e}")

adapter_var = tk.StringVar(root)
adapter_var.set(adapter_options[0])

adapter_dropdown = tk.OptionMenu(control_frame, adapter_var, *adapter_options)
adapter_dropdown.config(width=30)
adapter_dropdown.pack(side=tk.LEFT, padx=(0, 20))

protocol_var = tk.StringVar(root, value=list(PROTOCOL_FILTERS.keys())[0])
tk.Label(control_frame, text="Filter:").pack(side=tk.LEFT, padx=(10, 5))
protocol_dropdown = tk.OptionMenu(control_frame, protocol_var, *PROTOCOL_FILTERS.keys())
protocol_dropdown.config(width=20)
protocol_dropdown.pack(side=tk.LEFT, padx=(0, 20))

start_capture_button = tk.Button(
    control_frame, 
    text="Start Capture", 
    command=start_capture_action, 
    bg='green', 
    fg='white'
)
start_capture_button.pack(side=tk.LEFT, padx=5)

stop_capture_button = tk.Button(
    control_frame, 
    text="Stop Capture", 
    command=stop_capture_action, 
    bg='red', 
    fg='white', 
    state=tk.DISABLED
)
stop_capture_button.pack(side=tk.LEFT, padx=5)

logs_button = tk.Button(control_frame, text="Logs", command=show_logs)
logs_button.pack(side=tk.LEFT, padx=10)

captured_data_button = tk.Button(control_frame, text="Captured Data", command=show_captured_data)
captured_data_button.pack(side=tk.LEFT, padx=10)

status_label = tk.Label(root, text="Status: Ready.", bd=1, relief=tk.SUNKEN, anchor=tk.W)
status_label.pack(side=tk.BOTTOM, fill=tk.X)

attack_frame = tk.Frame(root, padx=10, pady=5)
attack_frame.pack(fill='both', expand=True)

tk.Label(attack_frame, text="Attack/Alert Log (Live):").pack(anchor='w')
attack_text = tk.Text(attack_frame, wrap=tk.WORD, height=25, width=100)
attack_text.pack(fill='both', expand=True)

root.after(100, check_packet_queue) 

root.mainloop()