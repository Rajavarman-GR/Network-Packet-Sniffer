import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import scapy.all as scapy

from ai.detector import ThreatDetector
from core.filter_engine import build_bpf_filter
from core.interfaces import get_network_interfaces, resolve_scapy_interface
from core.packet_manager import PacketManager
from core.parser import get_packet_metadata
from core.sniffer import PacketSniffer
from gui.settings_dialog import SettingsDialog
from utils.config import load_config, save_config
from utils.logger import log_error, log_warning
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
        self.dropped_packets = 0
        self.packet_manager = PacketManager(self._configured_max_packets())
        self.packet_rows = []
        self.packet_queue = queue.Queue(maxsize=1000)
        self.drain_after_id = None
        self.health_after_id = None
        self.io_queue = queue.Queue()
        self.io_poll_after_id = None
        self.io_busy = False
        self.current_sort_col = None
        self.current_sort_desc = False
        self.max_packets = self._configured_max_packets()
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

    def _configured_max_packets(self):
        try:
            return max(1, int(self.config.get("max_packets", 10000)))
        except (TypeError, ValueError):
            return 10000

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

        self.dropped_packets_label = tk.Label(stats, text="Dropped : 0", bg=PANEL_BG, fg=WARNING)
        self.dropped_packets_label.pack(anchor="w", padx=10)

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
            self.sniffer.start(
                resolve_scapy_interface(interface),
                self.packet_callback,
                filter_expression=build_bpf_filter(protocol),
            )
        except Exception as exc:
            self._show_capture_error(interface, exc)
            return

        self.bandwidth_start_time = time.time()
        self.bandwidth_bytes = 0
        self.status.config(text=f"Capturing on {interface}")
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.health_after_id = self.root.after(300, self._check_capture_health, interface)
        self._schedule_packet_drain()

    def _check_capture_health(self, interface):
        self.health_after_id = None
        if not self.sniffer.running:
            return

        capture = self.sniffer.sniffer
        exc = getattr(capture, "exception", None) if capture is not None else None
        if exc is not None:
            self.sniffer.stop()
            self._show_capture_error(interface, exc)
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            return

        if capture is None or not getattr(capture, "running", True):
            self.sniffer.stop()
            self.status.config(text="Capture stopped")
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            return

        self.health_after_id = self.root.after(300, self._check_capture_health, interface)

    def _show_capture_error(self, interface, exc):
        messagebox.showerror(
            "Capture Error",
            f"Could not start capture on {interface}.\n\n{exc}\n\nPacket capture usually requires root/administrator privileges.",
        )
        self.status.config(text="Ready")

    def stop_capture(self):
        if not self.sniffer.running:
            self._cancel_health_check()
            return

        self.sniffer.stop()
        self._cancel_health_check()
        self.status.config(text="Capture Stopped")
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def packet_callback(self, packet):
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            self.dropped_packets += 1
            log_warning("Packet queue full; dropping a packet before GUI processing")

    def _cancel_health_check(self):
        if self.health_after_id is None:
            return
        try:
            self.root.after_cancel(self.health_after_id)
        except tk.TclError:
            pass
        self.health_after_id = None

    def _schedule_packet_drain(self):
        if self.drain_after_id is None:
            self.drain_after_id = self.root.after(50, self._drain_packet_queue)

    def _drain_packet_queue(self):
        self.drain_after_id = None
        for _ in range(200):
            try:
                packet = self.packet_queue.get_nowait()
            except queue.Empty:
                break
            self._process_packet(packet, is_live=True)

        if self.sniffer.running or not self.packet_queue.empty():
            self._schedule_packet_drain()

    def _process_packet(self, packet, is_live=False, refresh=True):
        self.packet_count += 1
        if is_live:
            self.bandwidth_bytes += len(packet)
        metadata = get_packet_metadata(packet, self.config.get("timestamp_format", "%H:%M:%S"))

        if self.threat_detector.is_available():
            if self.threat_detector.detect(packet):
                self.threat_count += 1

        self._append_packet_row(packet, metadata, refresh=refresh)

    def _append_packet_row(self, packet, metadata, refresh=True):
        if metadata["protocol"] == "TCP":
            self.tcp_count += 1
        elif metadata["protocol"] == "UDP":
            self.udp_count += 1
        elif metadata["protocol"] == "ICMP" or metadata["protocol"] == "ICMPv6":
            self.icmp_count += 1

        record, evicted = self.packet_manager.add(packet, metadata)
        self.packet_rows = self.packet_manager.records()

        if evicted is not None and self.packet_table.exists(str(evicted["id"])):
            self.packet_table.delete(str(evicted["id"]))

        if refresh:
            self._insert_packet_row(record)
        self._update_statistics()

    def _insert_packet_row(self, row):
        values = (
            row["timestamp"], row["src"], row["dst"], row["protocol"],
            row["sport"], row["dport"], row["length"],
        )
        position = "end"
        if self.current_sort_col:
            new_value = self._sort_value(row, self.current_sort_col)
            visible = self.packet_table.get_children()
            for index, item in enumerate(visible):
                existing = self.packet_manager.get(item)
                if existing is None:
                    continue
                if (new_value < self._sort_value(existing, self.current_sort_col)) != self.current_sort_desc:
                    position = index
                    break
        self.packet_table.insert("", position, iid=str(row["id"]), values=values, tags=(row["protocol"],))
        if self.config.get("auto_scroll", True) and position == "end":
            self.packet_table.yview_moveto(1)

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

        for row in rows:
            values = (
                row["timestamp"],
                row["src"],
                row["dst"],
                row["protocol"],
                row["sport"],
                row["dport"],
                row["length"],
            )
            self.packet_table.insert("", "end", iid=str(row["id"]), values=values, tags=(row["protocol"],))

        if self.config.get("auto_scroll", True):
            self.packet_table.yview_moveto(1)

    def _update_statistics(self):
        self.total_packets.config(text=f"Packets : {self.packet_count}")
        self.tcp_packets.config(text=f"TCP : {self.tcp_count}")
        self.udp_packets.config(text=f"UDP : {self.udp_count}")
        self.icmp_packets.config(text=f"ICMP : {self.icmp_count}")
        self.dropped_packets_label.config(text=f"Dropped : {self.dropped_packets}")
        self.threats.config(text=f"Threats : {self.threat_count}")

        if self.bandwidth_start_time is not None:
            elapsed = time.time() - self.bandwidth_start_time
            if elapsed > 0:
                kbps = (self.bandwidth_bytes / 1024) / elapsed
                self.bandwidth.config(text=f"Bandwidth : {kbps:.1f} KB/s")

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
        row = self.packet_manager.get(iid)
        if row is None:
            return
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
        if self.io_busy:
            return
        rows = self.packet_manager.records()
        if not rows:
            messagebox.showinfo("Export", "No packets captured yet.")
            return

        filepath = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if not filepath:
            return

        if not validate_export_filename(filepath):
            messagebox.showerror("Export Error", "Please provide a valid export path.")
            return

        self.io_busy = True
        self.status.config(text="Exporting capture...")
        threading.Thread(
            target=self._export_worker,
            args=(filepath, [row["packet"] for row in rows], len(rows)),
            daemon=True,
        ).start()
        self._schedule_io_poll()

    def _export_worker(self, filepath, packets, packet_count):
        try:
            scapy.wrpcap(filepath, packets)
            result = ("export", filepath, packet_count, None)
        except Exception as exc:
            result = ("export", filepath, packet_count, exc)
        self.io_queue.put(result)

    def _schedule_io_poll(self):
        if self.io_poll_after_id is None:
            self.io_poll_after_id = self.root.after(50, self._poll_io_results)

    def _poll_io_results(self):
        self.io_poll_after_id = None
        try:
            operation, filepath, value, error = self.io_queue.get_nowait()
        except queue.Empty:
            if self.io_busy:
                self._schedule_io_poll()
            return

        self.io_busy = False
        if error is not None:
            title = "Open PCAP" if operation == "load" else "Export Error"
            messagebox.showerror(title, f"Could not process capture.\n\n{error}")
            self.status.config(text="Ready")
            return

        if operation == "load":
            self.new_capture()
            for packet in value:
                self._process_packet(packet, refresh=False)
            self._refresh_packet_table()
            self._update_statistics()
            self.status.config(text=f"Loaded {len(value)} packets from {filepath}")
        else:
            messagebox.showinfo("Export", f"Saved {value} packets to {filepath}")
            self.status.config(text="Ready")

    def create_statusbar(self):
        ai_state = "available" if self.threat_detector.is_available() else "unavailable"
        self.status = tk.Label(self.root, text=f" Ready | AI: {ai_state}", anchor="w", bg=HEADER_BG, fg="white", font=("Segoe UI", 10))
        self.status.pack(fill="x", side="bottom")

    def new_capture(self):
        self.stop_capture()
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except queue.Empty:
                break
        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.threat_count = 0
        self.dropped_packets = 0
        self.bandwidth_bytes = 0
        self.bandwidth_start_time = None
        self.packet_manager.clear()
        self.packet_rows = []
        self.packet_details.delete("1.0", "end")
        self._refresh_packet_table()
        self._update_statistics()
        self.status.config(text="New capture prepared")

    def open_pcap(self):
        if self.io_busy:
            return
        filepath = filedialog.askopenfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if not filepath:
            return

        self.io_busy = True
        self.status.config(text="Loading PCAP...")
        threading.Thread(target=self._load_pcap_worker, args=(filepath,), daemon=True).start()
        self._schedule_io_poll()

    def _load_pcap_worker(self, filepath):
        try:
            result = ("load", filepath, scapy.rdpcap(filepath), None)
        except Exception as exc:
            result = ("load", filepath, None, exc)
        self.io_queue.put(result)

    def open_settings(self):
        SettingsDialog(self.root, self.config, self._apply_settings)

    def _apply_settings(self, config):
        self.config = config
        self.max_packets = self._configured_max_packets()
        self.packet_manager.set_max_packets(self.max_packets)
        self.packet_rows = self.packet_manager.records()
        self._refresh_packet_table()
        self.apply_theme()
        save_config(self.config)
        self.status.config(text="Settings updated")

    def on_closing(self):
        try:
            self.stop_capture()
        except Exception as exc:
            log_error(f"Shutdown error: {exc}")
        self.root.destroy()

