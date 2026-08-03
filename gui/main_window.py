import time
import tkinter as tk
from tkinter import ttk

import scapy.all as scapy

from utils.constants import *
from core.interfaces import get_network_interfaces
from core.sniffer import PacketSniffer


class PacketSnifferApp:

    def __init__(self, root):

        self.root = root

        self.sniffer = PacketSniffer()

        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.packet_list = []

        self.configure_window()

        self.create_styles()

        self.create_menu()

        self.create_header()

        self.create_toolbar()

        self.create_body()

        self.create_statusbar()

    # --------------------------------------------------

    def configure_window(self):

        self.root.title("Advanced AI Network Packet Sniffer")

        self.root.geometry(
            f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}"
        )

        self.root.minsize(1200, 750)

        self.root.configure(bg=DARK_BG)

    # --------------------------------------------------

    def create_styles(self):

        style = ttk.Style()

        style.theme_use("clam")

        style.configure(
            "Treeview",
            background=TABLE_BG,
            foreground="white",
            fieldbackground=TABLE_BG,
            rowheight=28
        )

        style.configure(
            "Treeview.Heading",
            background=PRIMARY,
            foreground="white",
            font=("Segoe UI", 10, "bold")
        )

    # --------------------------------------------------

    def create_menu(self):

        menubar = tk.Menu(self.root)

        #################################################

        file_menu = tk.Menu(
            menubar,
            tearoff=0
        )

        file_menu.add_command(label="New Capture")

        file_menu.add_command(label="Open PCAP")

        file_menu.add_separator()

        file_menu.add_command(label="Export")

        file_menu.add_separator()

        file_menu.add_command(
            label="Exit",
            command=self.root.quit
        )

        #################################################

        capture_menu = tk.Menu(
            menubar,
            tearoff=0
        )

        capture_menu.add_command(label="Start Capture")

        capture_menu.add_command(label="Stop Capture")

        #################################################

        help_menu = tk.Menu(
            menubar,
            tearoff=0
        )

        help_menu.add_command(label="About")

        #################################################

        menubar.add_cascade(
            label="File",
            menu=file_menu
        )

        menubar.add_cascade(
            label="Capture",
            menu=capture_menu
        )

        menubar.add_cascade(
            label="Help",
            menu=help_menu
        )

        self.root.config(menu=menubar)

    # --------------------------------------------------

    def create_header(self):

        header = tk.Frame(
            self.root,
            bg=HEADER_BG,
            height=70
        )

        header.pack(
            fill="x"
        )

        title = tk.Label(
            header,
            text="Advanced AI Network Packet Sniffer",
            font=("Segoe UI", 22, "bold"),
            bg=HEADER_BG,
            fg="white"
        )

        title.pack(
            side="left",
            padx=20,
            pady=15
        )

        version = tk.Label(
            header,
            text="Version 2.0",
            bg=HEADER_BG,
            fg="#A0A0A0",
            font=("Segoe UI", 10)
        )

        version.pack(
            side="right",
            padx=20
        )

    def create_toolbar(self):

        toolbar = tk.Frame(
            self.root,
            bg=PANEL_BG,
            height=65
        )

        toolbar.pack(
            fill="x",
            padx=10,
            pady=(5, 0)
        )

        ####################################################
        # Interface
        ####################################################

        tk.Label(
            toolbar,
            text="Interface",
            bg=PANEL_BG,
            fg="white",
            font=("Segoe UI", 10)
        ).grid(row=0, column=0, padx=(15, 5), pady=15)

        self.interface_var = tk.StringVar()

        self.interface_combo = ttk.Combobox(
            toolbar,
            textvariable=self.interface_var,
            width=28,
            state="readonly"
        )

        self.interface_combo["values"] = get_network_interfaces()

        if self.interface_combo["values"]:
            self.interface_combo.current(0)

        self.interface_combo.grid(
            row=0,
            column=1
        )

        ####################################################
        # Protocol
        ####################################################

        tk.Label(
            toolbar,
            text="Protocol",
            bg=PANEL_BG,
            fg="white",
            font=("Segoe UI", 10)
        ).grid(row=0, column=2, padx=(30, 5))

        self.protocol_var = tk.StringVar()

        self.protocol_combo = ttk.Combobox(
            toolbar,
            textvariable=self.protocol_var,
            width=12,
            state="readonly",
            values=[
                "ALL",
                "TCP",
                "UDP",
                "ICMP",
                "ARP",
                "DNS"
            ]
        )

        self.protocol_combo.current(0)

        self.protocol_combo.grid(
            row=0,
            column=3
        )

        ####################################################
        # Buttons
        ####################################################

        self.start_button = tk.Button(
            toolbar,
            text="▶ Start",
            command=self.start_capture,
            bg=SUCCESS,
            fg="white",
            width=12,
            relief="flat",
            font=("Segoe UI", 10, "bold")
        )

        self.start_button.grid(
            row=0,
            column=4,
            padx=(40, 10)
        )

        ####################################################

        self.stop_button = tk.Button(
            toolbar,
            text="■ Stop",
            command=self.stop_capture,
            bg=ERROR,
            fg="white",
            width=12,
            relief="flat",
            font=("Segoe UI", 10, "bold")
        )

        self.stop_button.grid(
            row=0,
            column=5,
            padx=5
        )

        ####################################################

        self.export_button = tk.Button(
            toolbar,
            text="Export",
            bg=PRIMARY,
            fg="white",
            width=12,
            relief="flat",
            font=("Segoe UI", 10)
        )

        self.export_button.grid(
            row=0,
            column=6,
            padx=20
        )

        ####################################################

        self.settings_button = tk.Button(
            toolbar,
            text="Settings",
            bg=WARNING,
            fg="black",
            width=12,
            relief="flat",
            font=("Segoe UI", 10)
        )

        self.settings_button.grid(
            row=0,
            column=7
        )

    def create_body(self):

        self.body = tk.Frame(
            self.root,
            bg=DARK_BG
        )

        self.body.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        ########################################################
        # Left Panel (Packet Table)
        ########################################################

        self.left_panel = tk.Frame(
            self.body,
            bg=PANEL_BG
        )

        self.left_panel.pack(
            side="left",
            fill="both",
            expand=True
        )

        ########################################################
        # Right Panel (Details + Statistics)
        ########################################################

        self.right_panel = tk.Frame(
            self.body,
            bg=PANEL_BG,
            width=350
        )

        self.right_panel.pack(
            side="right",
            fill="y",
            padx=(10, 0)
        )

        self.right_panel.pack_propagate(False)

        self.create_packet_table()

        self.create_packet_details()

        self.create_statistics()

    # --------------------------------------------------

    def create_packet_table(self):

        title = tk.Label(
            self.left_panel,
            text="Captured Packets",
            bg=PANEL_BG,
            fg="white",
            font=("Segoe UI", 12, "bold")
        )

        title.pack(anchor="w", padx=15, pady=(15, 5))

        search_frame = tk.Frame(
            self.left_panel,
            bg=PANEL_BG
        )

        search_frame.pack(
            fill="x",
            padx=10
        )

        tk.Label(
            search_frame,
            text="Search",
            bg=PANEL_BG,
            fg="white"
        ).pack(side="left")

        self.search_entry = tk.Entry(
            search_frame,
            width=40
        )

        self.search_entry.pack(
            side="left",
            padx=10
        )

        tk.Button(
            search_frame,
            text="Find",
            command=self.search_packets
        ).pack(side="left")

        columns = (
            "Time",
            "Source",
            "Destination",
            "Protocol",
            "Src Port",
            "Dst Port",
            "Length"
        )

        self.packet_table = ttk.Treeview(
            self.left_panel,
            columns=columns,
            show="headings",
            height=25
        )

        widths = {
            "Time": 120,
            "Source": 170,
            "Destination": 170,
            "Protocol": 90,
            "Src Port": 80,
            "Dst Port": 80,
            "Length": 80
        }

        for col in columns:
            self.packet_table.heading(col, text=col)
            self.packet_table.column(
                col,
                width=widths[col],
                anchor="center"
            )

        self.packet_table.tag_configure(
            "TCP",
            background="#203864"
        )

        self.packet_table.tag_configure(
            "UDP",
            background="#2E5D34"
        )

        self.packet_table.tag_configure(
            "ICMP",
            background="#663300"
        )

        self.packet_table.tag_configure(
            "OTHER",
            background="#444444"
        )

        self.packet_table.bind(
            "<<TreeviewSelect>>",
            self.show_packet_details
        )

        self.packet_table.bind(
            "<Double-1>",
            self.show_packet_details
        )

        scrollbar = ttk.Scrollbar(
            self.left_panel,
            orient="vertical",
            command=self.packet_table.yview
        )

        self.packet_table.configure(
            yscrollcommand=scrollbar.set
        )

        self.packet_table.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(15, 0),
            pady=10
        )

        scrollbar.pack(
            side="right",
            fill="y",
            pady=10,
            padx=(0, 15)
        )

    # --------------------------------------------------

    def create_packet_details(self):

        title = tk.Label(
            self.right_panel,
            text="Packet Details",
            bg=PANEL_BG,
            fg="white",
            font=("Segoe UI", 12, "bold")
        )

        title.pack(anchor="w", padx=15, pady=(15, 5))

        self.packet_details = tk.Text(
            self.right_panel,
            height=20,
            bg=TABLE_BG,
            fg="white",
            insertbackground="white",
            relief="flat",
            wrap="word"
        )

        self.packet_details.pack(
            fill="x",
            padx=15
        )

    # --------------------------------------------------

    def create_statistics(self):

        stats = tk.LabelFrame(
            self.right_panel,
            text="Live Statistics",
            bg=PANEL_BG,
            fg="white",
            font=("Segoe UI", 11, "bold")
        )

        stats.pack(
            fill="x",
            padx=15,
            pady=20
        )

        self.total_packets = tk.Label(
            stats,
            text="Packets : 0",
            bg=PANEL_BG,
            fg="white",
            font=("Segoe UI", 10)
        )

        self.total_packets.pack(anchor="w", padx=10, pady=5)

        self.tcp_packets = tk.Label(
            stats,
            text="TCP : 0",
            bg=PANEL_BG,
            fg="white"
        )

        self.tcp_packets.pack(anchor="w", padx=10)

        self.udp_packets = tk.Label(
            stats,
            text="UDP : 0",
            bg=PANEL_BG,
            fg="white"
        )

        self.udp_packets.pack(anchor="w", padx=10)

        self.icmp_packets = tk.Label(
            stats,
            text="ICMP : 0",
            bg=PANEL_BG,
            fg="white"
        )

        self.icmp_packets.pack(anchor="w", padx=10)

        self.bandwidth = tk.Label(
            stats,
            text="Bandwidth : 0 KB/s",
            bg=PANEL_BG,
            fg="white"
        )

        self.bandwidth.pack(anchor="w", padx=10)

        self.threats = tk.Label(
            stats,
            text="Threats : 0",
            bg=PANEL_BG,
            fg="red",
            font=("Segoe UI", 10, "bold")
        )

        self.threats.pack(anchor="w", padx=10, pady=(5, 10))

    # --------------------------------------------------

    def start_capture(self):

        interface = self.interface_var.get()

        if interface == "":
            return

        self.status.config(
            text=f"Capturing on {interface}"
        )

        self.sniffer.start(
            interface,
            self.packet_callback
        )

    # --------------------------------------------------

    def stop_capture(self):

        self.sniffer.stop()

        self.status.config(
            text="Capture stopped"
        )

    # --------------------------------------------------

    def packet_callback(self, packet):

        self.packet_count += 1

        protocol = "OTHER"

        src = ""

        dst = ""

        sport = ""

        dport = ""

        if packet.haslayer(scapy.IP):

            src = packet[scapy.IP].src

            dst = packet[scapy.IP].dst

        if packet.haslayer(scapy.TCP):

            protocol = "TCP"

            sport = packet[scapy.TCP].sport

            dport = packet[scapy.TCP].dport

            self.tcp_count += 1

        elif packet.haslayer(scapy.UDP):

            protocol = "UDP"

            sport = packet[scapy.UDP].sport

            dport = packet[scapy.UDP].dport

            self.udp_count += 1

        elif packet.haslayer(scapy.ICMP):

            protocol = "ICMP"

            self.icmp_count += 1

        self.packet_list.append(packet)

        timestamp = time.strftime("%H:%M:%S")

        self.root.after(
            0,
            lambda: self.update_table(
                timestamp,
                src,
                dst,
                protocol,
                sport,
                dport,
                len(packet)
            )
        )

    # --------------------------------------------------

    def update_table(

        self,

        time,

        src,

        dst,

        protocol,

        sport,

        dport,

        length

    ):

        self.packet_table.insert(
            "",
            "end",
            values=(
                time,
                src,
                dst,
                protocol,
                sport,
                dport,
                length
            ),
            tags=(protocol,)
        )

        self.total_packets.config(
            text=f"Packets : {self.packet_count}"
        )

        self.tcp_packets.config(
            text=f"TCP : {self.tcp_count}"
        )

        self.udp_packets.config(
            text=f"UDP : {self.udp_count}"
        )

        self.icmp_packets.config(
            text=f"ICMP : {self.icmp_count}"
        )

        self.packet_table.yview_moveto(1)

    # --------------------------------------------------

    def show_packet_details(self, event):

        selected = self.packet_table.selection()

        if not selected:
            return

        index = self.packet_table.index(selected[0])

        packet = self.packet_list[index]

        self.packet_details.delete(
            "1.0",
            "end"
        )

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

        if packet.haslayer(scapy.Raw):

            payload = packet[scapy.Raw].load.decode("latin-1", errors="replace")

            details += "===== ASCII PAYLOAD =====\n"
            details += payload + "\n\n"

        details += "===== HEX DUMP =====\n\n"
        hexdump_output = scapy.hexdump(packet, dump=True)
        details += hexdump_output if hexdump_output is not None else ""

        self.packet_details.insert(
            "end",
            details
        )

    # --------------------------------------------------

    def search_packets(self):

        keyword = self.search_entry.get().lower()

        for row in self.packet_table.get_children():

            values = self.packet_table.item(row)["values"]

            text = " ".join(map(str, values)).lower()

            if keyword in text:

                self.packet_table.selection_set(row)
                self.packet_table.focus(row)
                self.packet_table.see(row)

                break

    # --------------------------------------------------

    def create_statusbar(self):

        self.status = tk.Label(
            self.root,
            text=" Ready",
            anchor="w",
            bg=HEADER_BG,
            fg="white",
            font=("Segoe UI", 10)
        )

        self.status.pack(
            fill="x",
            side="bottom"
        )