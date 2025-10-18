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