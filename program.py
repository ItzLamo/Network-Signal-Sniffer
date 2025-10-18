import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import *
from datetime import datetime
import threading
import json
import queue

class NetworkSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Signal Sniffer")
        self.root.geometry("900x600")
        
        self.packet_queue = queue.Queue()
        self.is_sniffing = False
        self.captured_packets = []
        
        self.setup_gui()
        self.setup_periodic_updates()
        
    def setup_gui(self):
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = ttk.Button(control_frame, text="Save Capture", command=self.save_capture)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        filter_frame = ttk.LabelFrame(self.root, text="Filters")
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Protocol:").pack(side=tk.LEFT, padx=5)
        self.protocol_var = tk.StringVar(value="ALL")
        protocol_combo = ttk.Combobox(filter_frame, textvariable=self.protocol_var, 
                                    values=["ALL", "TCP", "UDP", "ICMP"])
        protocol_combo.pack(side=tk.LEFT, padx=5)
        
        self.stats_frame = ttk.LabelFrame(self.root, text="Statistics")
        self.stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.stats_text = ttk.Label(self.stats_frame, text="Packets captured: 0")
        self.stats_text.pack(padx=5, pady=5)
        
        list_frame = ttk.Frame(self.root)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.tree = ttk.Treeview(list_frame, columns=("Time", "Source", "Destination", "Protocol", "Length"),
                                show="headings")
        
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length")
        
        self.tree.column("Time", width=150)
        self.tree.column("Source", width=150)
        self.tree.column("Destination", width=150)
        self.tree.column("Protocol", width=100)
        self.tree.column("Length", width=100)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.detail_frame = ttk.LabelFrame(self.root, text="Packet Details")
        self.detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.detail_text = scrolledtext.ScrolledText(self.detail_frame, height=10)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.tree.bind('<<TreeviewSelect>>', self.on_select_packet)
        
    def packet_callback(self, packet):
        if not self.is_sniffing:
            return
        
        packet_dict = self.parse_packet(packet)
        self.packet_queue.put(packet_dict)
        
    def parse_packet(self, packet):
        packet_dict = {
            "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "source": None,
            "destination": None,
            "protocol": None,
            "length": len(packet),
            "details": {}
        }
        
        if IP in packet:
            packet_dict["source"] = packet[IP].src
            packet_dict["destination"] = packet[IP].dst
            
            if TCP in packet:
                packet_dict["protocol"] = "TCP"
                packet_dict["details"]["sport"] = packet[TCP].sport
                packet_dict["details"]["dport"] = packet[TCP].dport
                packet_dict["details"]["flags"] = str(packet[TCP].flags)
            elif UDP in packet:
                packet_dict["protocol"] = "UDP"
                packet_dict["details"]["sport"] = packet[UDP].sport
                packet_dict["details"]["dport"] = packet[UDP].dport
            elif ICMP in packet:
                packet_dict["protocol"] = "ICMP"
                packet_dict["details"]["type"] = packet[ICMP].type
                packet_dict["details"]["code"] = packet[ICMP].code
        
        return packet_dict
    
    def start_capture(self):
        self.is_sniffing = True
        self.start_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        
        # Start sniffing in a separate thread
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        
    def stop_capture(self):
        self.is_sniffing = False
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
        
    def sniff_packets(self):
        try:
            sniff(prn=self.packet_callback, store=0, iface=conf.iface)
        except Exception as e:
            print(f"Sniffing error: {e}")
        
    def setup_periodic_updates(self):
        self.update_display()
        self.root.after(100, self.setup_periodic_updates)
        
    def update_display(self):
        try:
            while True:
                packet_dict = self.packet_queue.get_nowait()
                self.captured_packets.append(packet_dict)
                
                if self.protocol_var.get() == "ALL" or packet_dict["protocol"] == self.protocol_var.get():
                    self.tree.insert("", tk.END, values=(
                        packet_dict["time"],
                        packet_dict["source"],
                        packet_dict["destination"],
                        packet_dict["protocol"],
                        packet_dict["length"]
                    ))
                
                self.stats_text.configure(text=f"Packets captured: {len(self.captured_packets)}")
                
        except queue.Empty:
            pass
        
    def on_select_packet(self, event):
        selection = self.tree.selection()
        if not selection:
            return
            
        item = selection[0]
        index = self.tree.index(item)
        packet_dict = self.captured_packets[index]
        
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, json.dumps(packet_dict, indent=2))
        
    def save_capture(self):
        with open("capture.json", "w") as f:
            json.dump(self.captured_packets, f, indent=2)

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = NetworkSnifferGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"Error: {e}")
        print("Note: This script requires administrator privileges!")