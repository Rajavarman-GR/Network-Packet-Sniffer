import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import scapy.all as scapy

from ai.detector import ThreatDetector
from core.filter_engine import build_bpf_filter
from core.interfaces import get_network_interfaces
from core.parser import get_packet_metadata
from core.sniffer import PacketSniffer
from gui.settings_dialog import SettingsDialog
from utils.config import load_config, save_config
from utils.constants import (
    DARK_BG,
    HEADER_BG,
    PANEL_BG,
    TABLE_BG,
    PRIMARY,
    SUCCESS,
    ERROR,
    WARNING,
    WINDOW_WIDTH,
    WINDOW_HEIGHT,
)
from utils.validator import (
    validate_export_filename,
    validate_interface,
    validate_protocol,
)


class PacketSnifferApp:

    def __init__(self, root):
        self.root = root
        self.config = load_config()
        self.sniffer = PacketSniffer()
        self.threat_detector = ThreatDetector()

        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.threat_count = 0
        self.packet_rows = []
        self.current_sort_col = None
        self.current_sort_desc = False
        self.max_packets = int(self.config.get("max_packets", 10000))
        self.bandwidth_bytes = 0
        self.bandwidth_start_time = None

        self.configure_window()
        self.create_styles()
        self.create_menu()
        self.create_header()
        self.create_toolbar()
        self.create_body()
        self.create_statusbar()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.apply_theme()

    def configure_window(self):
        self.root.title("Advanced AI Network Packet Sniffer")
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.root.minsize(1200, 750)
        self.root.configure(bg=DARK_BG)

    def create_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=TABLE_BG,
            foreground="white",
            fieldbackground=TABLE_BG,
            rowheight=28,
        )
        style.configure(
            "Treeview.Heading",
            background=PRIMARY,
            foreground="white",
            font=("Segoe UI", 10, "bold"),
        )

    def create_menu(self):
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Capture", command=self.new_capture)
        file_menu.add_command(label="Open PCAP", command=self.open_pcap)
        file_menu.add_separator()
        file_menu.add_command(label="Export", command=self.export_packets)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)

        capture_menu = tk.Menu(menubar, tearoff=0)
        capture_menu.add_command(label="Start Capture", command=self.start_capture)
        capture_menu.add_command(label="Stop Capture", command=self.stop_capture)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(
            label="About",
            command=lambda: messagebox.showinfo(
                "About",
                "Advanced AI Network Packet Sniffer\nVersion 2.0",
            ),
        )

        menubar.add_cascade(label="File", menu=file_menu)
        menubar.add_cascade(label="Capture", menu=capture_menu)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

    def create_header(self):
        header = tk.Frame(self.root, bg=HEADER_BG, height=70)
        header.pack(fill="x")

        title = tk.Label(
            header,
            text="Advanced AI Network Packet Sniffer",
            font=("Segoe UI", 22, "bold"),
            bg=HEADER_BG,
            fg="white",
        )
        title.pack(side="left", padx=20, pady=15)

        version = tk.Label(
            header,
            text="Version 2.0",
            bg=HEADER_BG,
            fg="#A0A0A0",
            font=("Segoe UI", 10),
        )
        version.pack(side="right", padx=20)

    def create_toolbar(self):
        toolbar = tk.Frame(self.root, bg=PANEL_BG, height=65)
        toolbar.pack(fill="x", padx=10, pady=(5, 0))

        tk.Label(toolbar, text="Interface", bg=PANEL_BG, fg="white", font=("Segoe UI", 10)).grid(row=0, column=0, padx=(15, 5), pady=15)

        self.interface_var = tk.StringVar(value=self.config.get("default_interface", ""))
        self.interface_combo = ttk.Combobox(toolbar, textvariable=self.interface_var, width=28, state="readonly")
        self.interface_combo["values"] = get_network_interfaces()
        if self.interface_combo["values"]:
            if self.interface_var.get() in self.interface_combo["values"]:
                self.interface_combo.set(self.interface_var.get())
            else:
                self.interface_combo.current(0)
        self.interface_combo.grid(row=0, column=1)

        tk.Label(toolbar, text="Protocol", bg=PANEL_BG, fg="white", font=("Segoe UI", 10)).grid(row=0, column=2, padx=(30, 5))

        self.protocol_var = tk.StringVar(value=self.config.get("default_protocol", "ALL"))
        self.protocol_combo = ttk.Combobox(
            toolbar,
            textvariable=self.protocol_var,
            width=12,
            state="readonly",
            values=["ALL", "TCP", "UDP", "ICMP", "ARP", "DNS", "ICMPv6"],
        )
        self.protocol_combo.grid(row=0, column=3)

        self.start_button = tk.Button(
            toolbar,
            text="▶ Start",
            command=self.start_capture,
            bg=SUCCESS,
            fg="white",
            width=12,
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        self.start_button.grid(row=0, column=4, padx=(40, 10))

        self.stop_button = tk.Button(
            toolbar,
            text="■ Stop",
            command=self.stop_capture,
            bg=ERROR,
            fg="white",
            width=12,
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        self.stop_button.grid(row=0, column=5, padx=5)

        self.export_button = tk.Button(
            toolbar,
            text="Export",
            command=self.export_packets,
            bg=PRIMARY,
            fg="white",
            width=12,
            relief="flat",
            font=("Segoe UI", 10),
        )
        self.export_button.grid(row=0, column=6, padx=20)

        self.settings_button = tk.Button(
            toolbar,
            text="Settings",
            command=self.open_settings,
            bg=WARNING,
            fg="black",
            width=12,
            relief="flat",
            font=("Segoe UI", 10),
        )
        self.settings_button.grid(row=0, column=7)

    def create_body(self):
        self.body = tk.Frame(self.root, bg=DARK_BG)
        self.body.pack(fill="both", expand=True, padx=10, pady=10)

        self.left_panel = tk.Frame(self.body, bg=PANEL_BG)
        self.left_panel.pack(side="left", fill="both", expand=True)

        self.right_panel = tk.Frame(self.body, bg=PANEL_BG, width=350)
        self.right_panel.pack(side="right", fill="y", padx=(10, 0))
        self.right_panel.pack_propagate(False)

        self.create_packet_table()
        self.create_packet_details()
        self.create_statistics()

    def create_packet_table(self):
        title = tk.Label(self.left_panel, text="Captured Packets", bg=PANEL_BG, fg="white", font=("Segoe UI", 12, "bold"))
        title.pack(anchor="w", padx=15, pady=(15, 5))

        search_frame = tk.Frame(self.left_panel, bg=PANEL_BG)
        search_frame.pack(fill="x", padx=10)

        tk.Label(search_frame, text="Search", bg=PANEL_BG, fg="white").pack(side="left")
        self.search_entry = tk.Entry(search_frame, width=40)
        self.search_entry.pack(side="left", padx=10)
        tk.Button(search_frame, text="Find", command=self.search_packets).pack(side="left")

        columns = ("Time", "Source", "Destination", "Protocol", "Src Port", "Dst Port", "Length")
        self.packet_table = ttk.Treeview(self.left_panel, columns=columns, show="headings", height=25)

        widths = {
            "Time": 120,
            "Source": 170,
            "Destination": 170,
            "Protocol": 90,
            "Src Port": 80,
            "Dst Port": 80,
            "Length": 80,
        }

        for col in columns:
            self.packet_table.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))
            self.packet_table.column(col, width=widths[col], anchor="center")

        self.packet_table.tag_configure("TCP", background="#203864")
        self.packet_table.tag_configure("UDP", background="#2E5D34")
        self.packet_table.tag_configure("ICMP", background="#663300")
        self.packet_table.tag_configure("ICMPv6", background="#4C1D95")
        self.packet_table.tag_configure("OTHER", background="#444444")

        self.packet_table.bind("<<TreeviewSelect>>", self.show_packet_details)
        self.packet_table.bind("<Double-1>", self.show_packet_details)

        scrollbar = ttk.Scrollbar(self.left_panel, orient="vertical", command=self.packet_table.yview)
        self.packet_table.configure(yscrollcommand=scrollbar.set)
        self.packet_table.pack(side="left", fill="both", expand=True, padx=(15, 0), pady=10)
        scrollbar.pack(side="right", fill="y", pady=10, padx=(0, 15))

    def create_packet_details(self):
        title = tk.Label(self.right_panel, text="Packet Details", bg=PANEL_BG, fg="white", font=("Segoe UI", 12, "bold"))
        title.pack(anchor="w", padx=15, pady=(15, 5))

        self.packet_details = tk.Text(
            self.right_panel,
            height=20,
            bg=TABLE_BG,
            fg="white",
            insertbackground="white",
            relief="flat",
            wrap="word",
        )
        self.packet_details.pack(fill="x", padx=15)

    def create_statistics(self):
        stats = tk.LabelFrame(self.right_panel, text="Live Statistics", bg=PANEL_BG, fg="white", font=("Segoe UI", 11, "bold"))
        stats.pack(fill="x", padx=15, pady=20)

        self.total_packets = tk.Label(stats, text="Packets : 0", bg=PANEL_BG, fg="white", font=("Segoe UI", 10))
        self.total_packets.pack(anchor="w", padx=10, pady=5)

        self.tcp_packets = tk.Label(stats, text="TCP : 0", bg=PANEL_BG, fg="white")
        self.tcp_packets.pack(anchor="w", padx=10)

        self.udp_packets = tk.Label(stats, text="UDP : 0", bg=PANEL_BG, fg="white")
        self.udp_packets.pack(anchor="w", padx=10)

        self.icmp_packets = tk.Label(stats, text="ICMP : 0", bg=PANEL_BG, fg="white")
        self.icmp_packets.pack(anchor="w", padx=10)

        self.bandwidth = tk.Label(stats, text="Bandwidth : 0 KB/s", bg=PANEL_BG, fg="white")
        self.bandwidth.pack(anchor="w", padx=10)

        self.threats = tk.Label(stats, text="Threats : 0", bg=PANEL_BG, fg="red", font=("Segoe UI", 10, "bold"))
        self.threats.pack(anchor="w", padx=10, pady=(5, 10))

    def apply_theme(self):
        theme = self.config.get("theme", "dark")
        if theme == "light":
            self.root.configure(bg="#f3f4f6")
            self.body.configure(bg="#f3f4f6")
            self.left_panel.configure(bg="#ffffff")
            self.right_panel.configure(bg="#ffffff")
        else:
            self.root.configure(bg=DARK_BG)
            self.body.configure(bg=DARK_BG)
            self.left_panel.configure(bg=PANEL_BG)
            self.right_panel.configure(bg=PANEL_BG)

    def start_capture(self):
        interface = self.interface_var.get()
        protocol = self.protocol_var.get()

        if not validate_interface(interface):
            messagebox.showerror("Validation Error", "Please select a valid network interface.")
            return

        if not validate_protocol(protocol):
            messagebox.showerror("Validation Error", "Please select a valid protocol.")
            return

        try:
            self.sniffer.start(interface, self.packet_callback, filter_expression=build_bpf_filter(protocol))
        except Exception as exc:
            self._show_capture_error(interface, exc)
            return

        self.bandwidth_start_time = time.time()
        self.bandwidth_bytes = 0
        self.status.config(text=f"Capturing on {interface}")
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.root.after(300, self._check_capture_health, interface)

    def _check_capture_health(self, interface):
        exc = getattr(self.sniffer.sniffer, "exception", None)
        if exc is not None:
            self.sniffer.running = False
            self._show_capture_error(interface, exc)
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")

    def _show_capture_error(self, interface, exc):
        messagebox.showerror(
            "Capture Error",
            f"Could not start capture on {interface}.\n\n{exc}\n\nPacket capture usually requires root/administrator privileges.",
        )
        self.status.config(text="Ready")

    def stop_capture(self):
        if not self.sniffer.running:
            return

        self.sniffer.stop()
        self.status.config(text="Capture Stopped")
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def packet_callback(self, packet):
        selected_protocol = self.protocol_var.get()
        if selected_protocol and selected_protocol != "ALL":
            if not self._packet_matches_protocol(packet, selected_protocol):
                return

        self.packet_count += 1
        self.bandwidth_bytes += len(packet)
        metadata = get_packet_metadata(packet)

        if self.threat_detector.is_available():
            if self.threat_detector.detect(packet):
                self.threat_count += 1

        self._append_packet_row(packet, metadata)

    def _append_packet_row(self, packet, metadata, refresh=True):
        if metadata["protocol"] == "TCP":
            self.tcp_count += 1
        elif metadata["protocol"] == "UDP":
            self.udp_count += 1
        elif metadata["protocol"] == "ICMP" or metadata["protocol"] == "ICMPv6":
            self.icmp_count += 1

        while len(self.packet_rows) >= self.max_packets:
            self.packet_rows.pop(0)

        self.packet_rows.append(
            {
                "packet": packet,
                "timestamp": metadata["timestamp"],
                "src": metadata["src"],
                "dst": metadata["dst"],
                "protocol": metadata["protocol"],
                "sport": metadata["sport"],
                "dport": metadata["dport"],
                "length": metadata["length"],
            }
        )

        if refresh:
            self._refresh_packet_table()
        self._update_statistics()

    def _refresh_packet_table(self):
        for item in self.packet_table.get_children():
            self.packet_table.delete(item)

        rows = list(self.packet_rows)
        if self.current_sort_col:
            rows = sorted(
                rows,
                key=lambda row: self._sort_value(row, self.current_sort_col),
                reverse=self.current_sort_desc,
            )

        for index, row in enumerate(rows):
            values = (
                row["timestamp"],
                row["src"],
                row["dst"],
                row["protocol"],
                row["sport"],
                row["dport"],
                row["length"],
            )
            self.packet_table.insert("", "end", iid=str(index), values=values, tags=(row["protocol"],))

        if self.config.get("auto_scroll", True):
            self.packet_table.yview_moveto(1)

    def _update_statistics(self):
        self.total_packets.config(text=f"Packets : {self.packet_count}")
        self.tcp_packets.config(text=f"TCP : {self.tcp_count}")
        self.udp_packets.config(text=f"UDP : {self.udp_count}")
        self.icmp_packets.config(text=f"ICMP : {self.icmp_count}")
        self.threats.config(text=f"Threats : {self.threat_count}")

        if self.bandwidth_start_time is not None:
            elapsed = time.time() - self.bandwidth_start_time
            if elapsed > 0:
                kbps = (self.bandwidth_bytes / 1024) / elapsed
                self.bandwidth.config(text=f"Bandwidth : {kbps:.1f} KB/s")

    def _packet_matches_protocol(self, packet, selected_protocol):
        layer_map = {
            "TCP": scapy.TCP,
            "UDP": scapy.UDP,
            "ICMP": scapy.ICMP,
            "ARP": scapy.ARP,
            "DNS": scapy.DNS,
            "ICMPv6": scapy.ICMPv6EchoRequest,
        }

        layer = layer_map.get(selected_protocol)
        if layer is None:
            return True
        return packet.haslayer(layer)

    def sort_by_column(self, column_name):
        if self.current_sort_col == column_name:
            self.current_sort_desc = not self.current_sort_desc
        else:
            self.current_sort_col = column_name
            self.current_sort_desc = False
        self._refresh_packet_table()

    def _sort_value(self, row, column_name):
        value = {
            "Time": row["timestamp"],
            "Source": row["src"],
            "Destination": row["dst"],
            "Protocol": row["protocol"],
            "Src Port": row["sport"],
            "Dst Port": row["dport"],
            "Length": row["length"],
        }.get(column_name, "")

        if column_name in {"Src Port", "Dst Port", "Length"}:
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        return str(value).lower()

    def show_packet_details(self, event):
        selected = self.packet_table.selection()
        if not selected:
            return

        iid = selected[0]
        index = int(iid)
        row = self.packet_rows[index]
        packet = row["packet"]

        self.packet_details.delete("1.0", "end")
        details = ""

        if packet.haslayer(scapy.Ether):
            eth = packet[scapy.Ether]
            details += "===== Ethernet =====\n"
            details += f"Source MAC : {eth.src}\n"
            details += f"Destination MAC : {eth.dst}\n\n"

        if packet.haslayer(scapy.IP):
            ip = packet[scapy.IP]
            details += "===== IPv4 =====\n"
            details += f"Source IP : {ip.src}\n"
            details += f"Destination IP : {ip.dst}\n"
            details += f"TTL : {ip.ttl}\n"
            details += f"Protocol : {ip.proto}\n"
            details += f"Length : {ip.len}\n\n"
        elif packet.haslayer(scapy.IPv6):
            ip = packet[scapy.IPv6]
            details += "===== IPv6 =====\n"
            details += f"Source IP : {ip.src}\n"
            details += f"Destination IP : {ip.dst}\n"
            details += f"Hop Limit : {ip.hlim}\n"
            details += f"Length : {ip.plen}\n\n"

        if packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            details += "===== TCP =====\n"
            details += f"Source Port : {tcp.sport}\n"
            details += f"Destination Port : {tcp.dport}\n"
            details += f"Flags : {tcp.flags}\n"
            details += f"Sequence : {tcp.seq}\n"
            details += f"Acknowledgement : {tcp.ack}\n\n"
        elif packet.haslayer(scapy.UDP):
            udp = packet[scapy.UDP]
            details += "===== UDP =====\n"
            details += f"Source Port : {udp.sport}\n"
            details += f"Destination Port : {udp.dport}\n\n"
        elif packet.haslayer(scapy.ICMP):
            icmp = packet[scapy.ICMP]
            details += "===== ICMP =====\n"
            details += f"Type : {icmp.type}\n"
            details += f"Code : {icmp.code}\n\n"
        elif packet.haslayer(scapy.ICMPv6EchoRequest) or packet.haslayer(scapy.ICMPv6EchoReply):
            details += "===== ICMPv6 =====\n"
            details += "ICMPv6 message detected.\n\n"

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load.decode("latin-1", errors="replace")
            details += "===== ASCII PAYLOAD =====\n"
            details += payload + "\n\n"

        details += "===== HEX DUMP =====\n\n"
        hexdump_output = scapy.hexdump(packet, dump=True)
        details += hexdump_output if hexdump_output is not None else ""

        self.packet_details.insert("end", details)

    def search_packets(self):
        keyword = self.search_entry.get().lower()
        if not keyword:
            return

        rows = self.packet_table.get_children()
        current = self.packet_table.selection()
        start_index = rows.index(current[0]) + 1 if current and current[0] in rows else 0
        ordered = rows[start_index:] + rows[:start_index]

        for row in ordered:
            values = self.packet_table.item(row)["values"]
            text = " ".join(map(str, values)).lower()
            if keyword in text:
                self.packet_table.selection_set(row)
                self.packet_table.focus(row)
                self.packet_table.see(row)
                return

        messagebox.showinfo("Search", f"No matches found for '{keyword}'.")

    def export_packets(self):
        if not self.packet_rows:
            messagebox.showinfo("Export", "No packets captured yet.")
            return

        filepath = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if not filepath:
            return

        if not validate_export_filename(filepath):
            messagebox.showerror("Export Error", "Please provide a valid export path.")
            return

        try:
            scapy.wrpcap(filepath, [row["packet"] for row in self.packet_rows])
        except Exception as exc:
            messagebox.showerror("Export Error", f"Could not save capture.\n\n{exc}")
            return

        messagebox.showinfo("Export", f"Saved {len(self.packet_rows)} packets to {filepath}")

    def create_statusbar(self):
        self.status = tk.Label(self.root, text=" Ready", anchor="w", bg=HEADER_BG, fg="white", font=("Segoe UI", 10))
        self.status.pack(fill="x", side="bottom")

    def new_capture(self):
        self.stop_capture()
        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.threat_count = 0
        self.bandwidth_bytes = 0
        self.bandwidth_start_time = None
        self.packet_rows = []
        self.packet_details.delete("1.0", "end")
        self._refresh_packet_table()
        self._update_statistics()
        self.status.config(text="New capture prepared")

    def open_pcap(self):
        filepath = filedialog.askopenfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if not filepath:
            return

        try:
            packets = scapy.rdpcap(filepath)
        except Exception as exc:
            messagebox.showerror("Open PCAP", f"Could not open file.\n\n{exc}")
            return

        self.new_capture()
        for packet in packets:
            metadata = get_packet_metadata(packet)
            self._append_packet_row(packet, metadata, refresh=False)
        self._refresh_packet_table()
        self._update_statistics()
        self.status.config(text=f"Loaded {len(packets)} packets from {filepath}")

    def open_settings(self):
        SettingsDialog(self.root, self.config, self._apply_settings)

    def _apply_settings(self, config):
        self.config = config
        self.max_packets = int(self.config.get("max_packets", 10000))
        self.apply_theme()
        save_config(self.config)
        self.status.config(text="Settings updated")

    def on_closing(self):
        try:
            self.stop_capture()
        except Exception as exc:
            print(f"Shutdown Error: {exc}")
        self.root.destroy()

