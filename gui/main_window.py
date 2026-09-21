import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import scapy.all as scapy

from ai.detector import ThreatDetector
from ai.feature_extractor import extract_features
from ai.flow_tracker import FlowTracker
from core.filter_engine import build_bpf_filter
from core.interfaces import get_network_interfaces, resolve_scapy_interface
from core.packet_manager import PacketManager
from core.parser import get_packet_metadata, get_payload_preview, matches_display_filter
from core.sniffer import PacketSniffer
from gui.settings_dialog import SettingsDialog
from utils.config import load_config
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
        self.flow_tracker = FlowTracker()
        self.ai_queue = queue.Queue(maxsize=1000)
        self.ai_result_queue = queue.Queue(maxsize=1000)
        self.ai_stop_event = threading.Event()
        self.ai_thread = None
        self.ai_result_after_id = None

        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.threat_count = 0
        self.suspicious_count = 0
        self.high_risk_count = 0
        self.dropped_packets = 0
        self.dns_count = 0
        self.arp_count = 0
        self.other_count = 0
        self.icmpv6_count = 0
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
        self.display_protocol_var = None
        self.display_filter = "ALL"
        self.search_keyword = ""

        self.configure_window()
        self.create_styles()
        self.create_menu()
        self.create_header()
        self.create_toolbar()
        self.create_body()
        self.create_statusbar()
        self._start_ai_worker()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.bind("<Control-o>", lambda event: self.open_pcap())
        self.root.bind("<Control-s>", lambda event: self.export_packets())
        self.root.bind("<F5>", lambda event: self.start_capture())
        self.apply_theme()

    def _configured_max_packets(self):
        try:
            return max(1, int(self.config.get("max_packets", 10000)))
        except (TypeError, ValueError):
            return 10000

    def configure_window(self):
        self.root.title("Network Packet Sniffer")
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.root.minsize(1000, 650)
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
                "Network Packet Sniffer\nVersion 2.0",
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
            text="Network Packet Sniffer",
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

        tk.Label(toolbar, text="Capture filter", bg=PANEL_BG, fg="white", font=("Segoe UI", 10)).grid(row=0, column=2, padx=(20, 5))

        self.protocol_var = tk.StringVar(value=self.config.get("default_protocol", "ALL"))
        self.protocol_combo = ttk.Combobox(
            toolbar,
            textvariable=self.protocol_var,
            width=12,
            state="readonly",
            values=["ALL", "TCP", "UDP", "ICMP", "ARP", "DNS", "ICMPv6"],
        )
        self.protocol_combo.grid(row=0, column=3)
        self.protocol_combo.bind("<<ComboboxSelected>>", lambda event: self._set_status_capture_filter())

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
        self.start_button.grid(row=0, column=4, padx=(20, 8))

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
        self.export_button.grid(row=0, column=6, padx=(12, 8))

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
        self.settings_button.grid(row=0, column=7, padx=(0, 12))

    def create_body(self):
        self.body = tk.Frame(self.root, bg=DARK_BG)
        self.body.pack(fill="both", expand=True, padx=10, pady=10)

        self.left_panel = tk.Frame(self.body, bg=PANEL_BG)
        self.left_panel.pack(side="left", fill="both", expand=True)

        self.right_panel = tk.Frame(self.body, bg=PANEL_BG, width=320)
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

        tk.Label(search_frame, text="Display filter", bg=PANEL_BG, fg="white").pack(side="left")
        self.search_entry = tk.Entry(search_frame, width=28)
        self.search_entry.pack(side="left", padx=(8, 5), fill="x", expand=True)
        self.search_entry.bind("<Return>", lambda event: self.apply_display_filter())
        self.search_entry.bind("<Escape>", lambda event: self.clear_display_filter())
        clear_button = tk.Button(search_frame, text="Clear", command=self.clear_display_filter)
        clear_button.pack(side="left", padx=(0, 8))
        self.display_protocol_var = tk.StringVar(value="ALL")
        self.display_protocol_combo = ttk.Combobox(
            search_frame,
            textvariable=self.display_protocol_var,
            state="readonly",
            width=10,
            values=["ALL", "TCP", "UDP", "DNS", "ARP", "ICMP", "ICMPv6", "Other"],
        )
        self.display_protocol_combo.pack(side="left")
        self.display_protocol_combo.bind("<<ComboboxSelected>>", lambda event: self.apply_display_filter())

        self.result_label = tk.Label(
            self.left_panel,
            text="No packets captured yet. Select an interface and click Start Capture.",
            bg=PANEL_BG,
            fg="#A0A0A0",
            anchor="w",
        )
        self.result_label.pack(fill="x", padx=15, pady=(4, 0))

        columns = ("Time", "Source", "Destination", "Protocol", "Src Port", "Dst Port", "Length", "AI")
        table_frame = tk.Frame(self.left_panel, bg=PANEL_BG)
        table_frame.pack(fill="both", expand=True, padx=10, pady=6)
        self.packet_table = ttk.Treeview(table_frame, columns=columns, show="headings")

        widths = {
            "Time": 120,
            "Source": 220,
            "Destination": 220,
            "Protocol": 90,
            "Src Port": 80,
            "Dst Port": 80,
            "Length": 80,
            "AI": 100,
        }

        for col in columns:
            self.packet_table.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))
            self.packet_table.column(col, width=widths[col], anchor="center")

        self.packet_table.tag_configure("TCP", background="#203864")
        self.packet_table.tag_configure("UDP", background="#2E5D34")
        self.packet_table.tag_configure("ICMP", background="#663300")
        self.packet_table.tag_configure("ICMPv6", background="#4C1D95")
        self.packet_table.tag_configure("DNS", background="#155E75")
        self.packet_table.tag_configure("ARP", background="#854D0E")
        self.packet_table.tag_configure("AI_SUSPICIOUS", foreground="#FBBF24")
        self.packet_table.tag_configure("AI_HIGH_RISK", foreground="#F87171")
        self.packet_table.tag_configure("OTHER", background="#444444")

        self.packet_table.bind("<<TreeviewSelect>>", self.show_packet_details)
        self.packet_table.bind("<Double-1>", self.show_packet_details)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.packet_table.yview)
        horizontal_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.packet_table.xview)
        self.packet_table.configure(yscrollcommand=scrollbar.set, xscrollcommand=horizontal_scrollbar.set)
        self.packet_table.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        horizontal_scrollbar.grid(row=1, column=0, sticky="ew")
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

    def create_packet_details(self):
        title = tk.Label(self.right_panel, text="Packet Details", bg=PANEL_BG, fg="white", font=("Segoe UI", 12, "bold"))
        title.pack(anchor="w", padx=15, pady=(15, 5))

        details_frame = tk.Frame(self.right_panel, bg=PANEL_BG)
        details_frame.pack(fill="both", expand=True, padx=15)
        self.packet_details = tk.Text(
            details_frame,
            bg=TABLE_BG,
            fg="white",
            insertbackground="white",
            relief="flat",
            wrap="word",
        )
        details_scrollbar = ttk.Scrollbar(details_frame, orient="vertical", command=self.packet_details.yview)
        self.packet_details.configure(yscrollcommand=details_scrollbar.set)
        self.packet_details.pack(side="left", fill="both", expand=True)
        details_scrollbar.pack(side="right", fill="y")

    def create_statistics(self):
        stats = tk.LabelFrame(self.right_panel, text="Packet Statistics", bg=PANEL_BG, fg="white", font=("Segoe UI", 10, "bold"))
        stats.pack(fill="x", padx=15, pady=(8, 15))
        self.stat_labels = {}
        stat_names = ["Captured", "Displayed", "TCP", "UDP", "DNS", "ARP", "ICMP", "ICMPv6", "Other", "Dropped", "Threats", "Suspicious", "High Risk", "AI Status"]
        for index, name in enumerate(stat_names):
            row, column = divmod(index, 2)
            tk.Label(stats, text=name, bg=PANEL_BG, fg="#A0A0A0", anchor="w").grid(row=row, column=column * 2, sticky="w", padx=(8, 2), pady=2)
            value = tk.Label(stats, text="Unavailable" if name == "AI Status" else "0", bg=PANEL_BG, fg="white", anchor="e", width=12 if name == "AI Status" else 8)
            value.grid(row=row, column=column * 2 + 1, sticky="e", padx=(0, 8), pady=2)
            self.stat_labels[name] = value
        self.total_packets = self.stat_labels["Captured"]
        self.tcp_packets = self.stat_labels["TCP"]
        self.udp_packets = self.stat_labels["UDP"]
        self.icmp_packets = self.stat_labels["ICMP"]
        self.dropped_packets_label = self.stat_labels["Dropped"]
        self.threats = self.stat_labels["Threats"]
        self.stat_labels["AI Status"].config(fg=WARNING)
        self.bandwidth = tk.Label(stats, text="Bandwidth: 0 KB/s", bg=PANEL_BG, fg="white")
        self.bandwidth.grid(row=7, column=0, columnspan=4, sticky="w", padx=8, pady=(5, 8))

    def _start_ai_worker(self):
        if not self.threat_detector.is_available():
            self.stat_labels["AI Status"].config(text="Unavailable")
            return
        self.stat_labels["AI Status"].config(text="Available")
        self.ai_thread = threading.Thread(target=self._ai_worker, daemon=True)
        self.ai_thread.start()
        self.ai_result_after_id = self.root.after(100, self._poll_ai_results)

    def _ai_worker(self):
        while not self.ai_stop_event.is_set():
            try:
                packet_id, packet, metadata = self.ai_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                packet_time = getattr(packet, "time", None)
                context = self.flow_tracker.observe(packet, metadata, packet_time)
                features = extract_features(packet, metadata, context)
                result = self.threat_detector.predict(features)
            except Exception:
                result = {"available": False, "label": "UNAVAILABLE", "confidence": None, "risk_score": None, "model_version": None}
            try:
                self.ai_result_queue.put_nowait((packet_id, result))
            except queue.Full:
                log_warning("AI result queue full; discarding an analysis result")

    def _poll_ai_results(self):
        self.ai_result_after_id = None
        while True:
            try:
                packet_id, result = self.ai_result_queue.get_nowait()
            except queue.Empty:
                break
            record = self.packet_manager.update(packet_id, {"ai_result": result})
            if record is None:
                continue
            label = result.get("label", "UNAVAILABLE")
            if result.get("available") and label == "SUSPICIOUS":
                self.suspicious_count += 1
            elif result.get("available") and label == "HIGH RISK":
                self.high_risk_count += 1
            if result.get("available") and label in {"SUSPICIOUS", "HIGH RISK"}:
                self.threat_count += 1
            item_id = str(packet_id)
            if self.packet_table.exists(item_id):
                self.packet_table.set(item_id, "AI", label)
                record_tags = self._row_tags(record)
                self.packet_table.item(item_id, tags=record_tags)
            if self.packet_table.selection() and self.packet_table.selection()[0] == item_id:
                self.show_packet_details(None)
            self._update_statistics()
        if self.ai_thread is not None and not self.ai_stop_event.is_set():
            self.ai_result_after_id = self.root.after(100, self._poll_ai_results)

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

    def _set_status_capture_filter(self):
        self.status.config(text=f"Capture filter ready: {self.protocol_var.get()}")

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

        record = self._append_packet_row(packet, metadata, refresh=refresh)
        if self.ai_thread is not None:
            try:
                self.ai_queue.put_nowait((record["id"], packet, metadata))
            except queue.Full:
                log_warning("AI queue full; skipping threat analysis for a packet")

    def _append_packet_row(self, packet, metadata, refresh=True):
        counters = {
            "TCP": "tcp_count",
            "UDP": "udp_count",
            "DNS": "dns_count",
            "ARP": "arp_count",
            "ICMP": "icmp_count",
            "ICMPv6": "icmpv6_count",
        }
        counter_name = counters.get(metadata["protocol"])
        if counter_name:
            setattr(self, counter_name, getattr(self, counter_name) + 1)
        else:
            self.other_count += 1

        record, evicted = self.packet_manager.add(packet, metadata)
        record["ai_result"] = None if self.threat_detector.is_available() else {
            "available": False,
            "label": "UNAVAILABLE",
            "confidence": None,
            "risk_score": None,
            "model_version": None,
        }
        self.packet_rows = self.packet_manager.records()

        if evicted is not None and self.packet_table.exists(str(evicted["id"])):
            self.packet_table.delete(str(evicted["id"]))

        if refresh and self._row_matches_display(record):
            self._insert_packet_row(record)
        elif refresh:
            self._update_result_label(len(self.packet_table.get_children()))
        self._update_statistics()
        return record

    def _insert_packet_row(self, row):
        values = (
            row["timestamp"], row["src"], row["dst"], row["protocol"],
            row["sport"], row["dport"], row["length"], self._ai_label(row),
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
        self.packet_table.insert("", position, iid=str(row["id"]), values=values, tags=self._row_tags(row))
        if self.config.get("auto_scroll", True) and position == "end":
            self.packet_table.yview_moveto(1)
        self._update_result_label(len(self.packet_table.get_children()))

    def _refresh_packet_table(self):
        for item in self.packet_table.get_children():
            self.packet_table.delete(item)

        rows = [row for row in self.packet_rows if self._row_matches_display(row)]
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
                self._ai_label(row),
            )
            self.packet_table.insert("", "end", iid=str(row["id"]), values=values, tags=self._row_tags(row))

        if self.config.get("auto_scroll", True):
            self.packet_table.yview_moveto(1)
        self._update_result_label(len(rows))

    @staticmethod
    def _ai_label(row):
        if row.get("ai_result") is None:
            return "Pending"
        result = row["ai_result"]
        return result.get("label", "Unavailable") if result.get("available") else "Unavailable"

    def _row_tags(self, row):
        tags = [row.get("protocol", "OTHER")]
        label = self._ai_label(row)
        if label == "SUSPICIOUS":
            tags.append("AI_SUSPICIOUS")
        elif label == "HIGH RISK":
            tags.append("AI_HIGH_RISK")
        return tuple(tags)

    def _update_statistics(self):
        self.total_packets.config(text=f"{self.packet_count:,}")
        self.stat_labels["Displayed"].config(text=f"{len(self.packet_manager):,}")
        self.tcp_packets.config(text=f"{self.tcp_count:,}")
        self.udp_packets.config(text=f"{self.udp_count:,}")
        self.stat_labels["DNS"].config(text=f"{self.dns_count:,}")
        self.stat_labels["ARP"].config(text=f"{self.arp_count:,}")
        self.icmp_packets.config(text=f"{self.icmp_count:,}")
        self.stat_labels["ICMPv6"].config(text=f"{self.icmpv6_count:,}")
        self.stat_labels["Other"].config(text=f"{self.other_count:,}")
        self.dropped_packets_label.config(text=f"{self.dropped_packets:,}")
        self.threats.config(text=f"{self.threat_count:,}")
        self.stat_labels["Suspicious"].config(text=f"{self.suspicious_count:,}")
        self.stat_labels["High Risk"].config(text=f"{self.high_risk_count:,}")
        self.stat_labels["AI Status"].config(text="Available" if self.threat_detector.is_available() else "Unavailable")

        if self.bandwidth_start_time is not None:
            elapsed = time.time() - self.bandwidth_start_time
            if elapsed > 0:
                kbps = (self.bandwidth_bytes / 1024) / elapsed
                self.bandwidth.config(text=f"Bandwidth : {kbps:.1f} KB/s")

    def _row_matches_display(self, row):
        protocol = self.display_protocol_var.get() if self.display_protocol_var is not None else "ALL"
        keyword = self.search_keyword.strip().lower()
        return matches_display_filter(row["packet"], row, protocol, keyword)

    def _update_result_label(self, visible_count=None):
        retained = len(self.packet_manager)
        visible_count = len(self._visible_records()) if visible_count is None else visible_count
        if not retained:
            text = "No packets captured yet. Select an interface and click Start Capture."
        elif not visible_count:
            text = "No packets match your current display filter."
        else:
            text = f"Showing {visible_count:,} of {retained:,} retained packets"
        self.result_label.config(text=text)

    def _visible_records(self):
        return [row for row in self.packet_manager.records() if self._row_matches_display(row)]

    def apply_display_filter(self):
        self.search_keyword = self.search_entry.get().strip()
        self.display_filter = self.display_protocol_var.get()
        self._refresh_packet_table()
        status = f"Display filter: {self.display_filter}"
        if self.search_keyword:
            status += f" | Search: {self.search_keyword}"
        self.status.config(text=status)

    def clear_display_filter(self):
        self.search_entry.delete(0, "end")
        self.display_protocol_var.set("ALL")
        self.search_keyword = ""
        self.display_filter = "ALL"
        self._refresh_packet_table()
        self.status.config(text="Display filter cleared")

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
        details = [f"===== Packet #{row['id']} Summary ====="]
        ai_result = row.get("ai_result")
        ai_label = self._ai_label(row)
        details.extend([
            "===== AI ANALYSIS =====",
            f"Prediction: {ai_label}",
            f"Confidence: {self._format_confidence(ai_result.get('confidence') if ai_result else None)}",
            f"Risk Score: {self._format_value(ai_result.get('risk_score') if ai_result else None)}",
            f"Model: {(ai_result or {}).get('model_version') or ('Pending' if ai_result is None else 'No compatible model loaded.')}",
            "",
        ])
        details.append(f"Protocol : {row['protocol']}")
        details.append(f"Source : {row['src']}")
        details.append(f"Destination : {row['dst']}")
        details.append(f"Source Port : {row['sport']}")
        details.append(f"Destination Port : {row['dport']}")
        details.append(f"Length : {row['length']}")
        details.append(f"Timestamp : {row['timestamp']}\n")

        if packet.haslayer(scapy.Ether):
            eth = packet[scapy.Ether]
            details.extend(["===== Ethernet =====", f"Source MAC : {eth.src}", f"Destination MAC : {eth.dst}", ""])

        if packet.haslayer(scapy.IP):
            ip = packet[scapy.IP]
            details.extend(["===== IPv4 =====", f"Source IP : {ip.src}", f"Destination IP : {ip.dst}", f"TTL : {ip.ttl}", f"Protocol : {ip.proto}", f"Length : {ip.len}", ""])
        elif packet.haslayer(scapy.IPv6):
            ip = packet[scapy.IPv6]
            details.extend(["===== IPv6 =====", f"Source IP : {ip.src}", f"Destination IP : {ip.dst}", f"Hop Limit : {ip.hlim}", f"Length : {ip.plen}", ""])

        if packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            details.extend(["===== TCP =====", f"Source Port : {tcp.sport}", f"Destination Port : {tcp.dport}", f"Flags : {tcp.flags}", f"Sequence : {tcp.seq}", f"Acknowledgement : {tcp.ack}", ""])
        elif packet.haslayer(scapy.UDP):
            udp = packet[scapy.UDP]
            details.extend(["===== UDP =====", f"Source Port : {udp.sport}", f"Destination Port : {udp.dport}", ""])
        elif packet.haslayer(scapy.ICMP):
            icmp = packet[scapy.ICMP]
            details.extend(["===== ICMP =====", f"Type : {icmp.type}", f"Code : {icmp.code}", ""])
        elif packet.haslayer(scapy.ICMPv6EchoRequest) or packet.haslayer(scapy.ICMPv6EchoReply):
            details.extend(["===== ICMPv6 =====", "ICMPv6 message detected.", ""])

        payload = get_payload_preview(packet)
        if payload["present"]:
            details.extend(["===== Payload ====="])
            if payload["printable"]:
                details.extend(["ASCII / Text Payload", payload["text"]])
            else:
                details.append("Binary payload detected. Showing hexadecimal representation.")
            if payload["truncated"]:
                details.append("[Payload truncated to first 4096 bytes]")
            details.extend(["", "===== Hex =====", payload["hex"], ""])

        details.extend(["===== Packet Hex Dump =====", ""])
        packet_bytes = bytes(packet)
        hexdump_output = scapy.hexdump(packet_bytes[:4096], dump=True)
        details.append(hexdump_output if hexdump_output is not None else "")
        if len(packet_bytes) > 4096:
            details.append("[Packet hex truncated to first 4096 bytes]")

        self.packet_details.insert("end", "\n".join(details))

    @staticmethod
    def _format_confidence(value):
        return "Unavailable" if value is None else f"{value:.2%}"

    @staticmethod
    def _format_value(value):
        return "Unavailable" if value is None else str(value)

    def search_packets(self):
        self.apply_display_filter()

    def export_packets(self):
        if self.io_busy:
            return
        rows = self._visible_records()
        if not rows:
            messagebox.showinfo("Export", "No retained packets match the current display filter.")
            return

        filepath = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if not filepath:
            return

        if not validate_export_filename(filepath):
            messagebox.showerror("Export Error", "Please provide a valid export path.")
            return

        self.io_busy = True
        self.status.config(text=f"Exporting {len(rows):,} filtered packets...")
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
            self.status.config(text=f"Loaded {len(value):,} packets | Displayed {len(self._visible_records()):,}")
        else:
            messagebox.showinfo("Export", f"Exported {value:,} packets from the current display view to {filepath}")
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
        self.dns_count = 0
        self.arp_count = 0
        self.other_count = 0
        self.icmpv6_count = 0
        self.suspicious_count = 0
        self.high_risk_count = 0
        self.bandwidth_bytes = 0
        self.bandwidth_start_time = None
        self.packet_manager.clear()
        self.flow_tracker.clear()
        while not self.ai_queue.empty():
            try:
                self.ai_queue.get_nowait()
            except queue.Empty:
                break
        while not self.ai_result_queue.empty():
            try:
                self.ai_result_queue.get_nowait()
            except queue.Empty:
                break
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
        self.interface_var.set(config.get("default_interface", self.interface_var.get()))
        self.protocol_var.set(config.get("default_protocol", self.protocol_var.get()))
        self.max_packets = self._configured_max_packets()
        self.packet_manager.set_max_packets(self.max_packets)
        self.packet_rows = self.packet_manager.records()
        self._refresh_packet_table()
        self._update_statistics()
        self.apply_theme()
        self.status.config(text="Settings updated")

    def on_closing(self):
        try:
            self.stop_capture()
            self.ai_stop_event.set()
            if self.ai_result_after_id is not None:
                self.root.after_cancel(self.ai_result_after_id)
        except Exception as exc:
            log_error(f"Shutdown error: {exc}")
        self.root.destroy()

