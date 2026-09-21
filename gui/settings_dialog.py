import tkinter as tk
import time
from tkinter import messagebox, ttk

from core.interfaces import get_network_interfaces
from utils.config import normalize_config, save_config


class SettingsDialog(tk.Toplevel):
    def __init__(self, parent, config, on_save=None):
        super().__init__(parent)
        self.title("Settings")
        self.transient(parent)
        self.grab_set()
        self.bind("<Escape>", lambda event: self.destroy())

        self.config = dict(config)
        self.on_save = on_save

        self.theme_var = tk.StringVar(value=self.config.get("theme", "dark"))
        self.max_packets_var = tk.StringVar(value=str(self.config.get("max_packets", 10000)))
        self.interface_var = tk.StringVar(value=self.config.get("default_interface", ""))
        self.protocol_var = tk.StringVar(value=self.config.get("default_protocol", "ALL"))
        self.auto_scroll_var = tk.BooleanVar(value=self.config.get("auto_scroll", True))
        self.timestamp_var = tk.StringVar(value=self.config.get("timestamp_format", "%H:%M:%S"))

        self._build_ui()

    def _build_ui(self):
        frame = ttk.Frame(self, padding=12)
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frame, text="Theme:").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Combobox(
            frame,
            textvariable=self.theme_var,
            state="readonly",
            values=["dark", "light"],
            width=20,
        ).grid(row=0, column=1, sticky="ew", pady=4)

        ttk.Label(frame, text="Max Packets:").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.max_packets_var, width=20).grid(row=1, column=1, sticky="ew", pady=4)

        ttk.Label(frame, text="Default Interface:").grid(row=2, column=0, sticky="w", pady=4)
        interface_combo = ttk.Combobox(
            frame,
            textvariable=self.interface_var,
            state="readonly",
            values=get_network_interfaces(),
            width=20,
        )
        interface_combo.grid(row=2, column=1, sticky="ew", pady=4)

        ttk.Label(frame, text="Default Protocol:").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Combobox(
            frame,
            textvariable=self.protocol_var,
            state="readonly",
            values=["ALL", "TCP", "UDP", "ICMP", "ARP", "DNS", "ICMPv6"],
            width=20,
        ).grid(row=3, column=1, sticky="ew", pady=4)

        ttk.Checkbutton(frame, text="Auto-scroll", variable=self.auto_scroll_var).grid(row=4, column=0, columnspan=2, sticky="w", pady=6)

        ttk.Label(frame, text="Timestamp Format:").grid(row=5, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.timestamp_var, width=20).grid(row=5, column=1, sticky="ew", pady=4)

        buttons = ttk.Frame(frame)
        buttons.grid(row=6, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(buttons, text="Save", command=self._save).pack(side="right")
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right", padx=(0, 6))

    def _save(self):
        try:
            max_packets = int(self.max_packets_var.get())
        except (TypeError, ValueError):
            messagebox.showerror("Invalid settings", "Maximum packets must be a whole number of at least 1.", parent=self)
            return
        if max_packets < 1:
            messagebox.showerror("Invalid settings", "Maximum packets must be at least 1.", parent=self)
            return

        timestamp_format = self.timestamp_var.get().strip() or "%H:%M:%S"
        try:
            time.strftime(timestamp_format)
        except (TypeError, ValueError):
            messagebox.showerror("Invalid settings", "Timestamp format is not valid.", parent=self)
            return

        self.config.update(
            {
                "theme": self.theme_var.get(),
                "max_packets": max_packets,
                "default_interface": self.interface_var.get(),
                "default_protocol": self.protocol_var.get(),
                "auto_scroll": bool(self.auto_scroll_var.get()),
                "timestamp_format": timestamp_format,
            }
        )
        self.config = normalize_config(self.config)

        save_config(self.config)
        if self.on_save is not None:
            self.on_save(self.config)
        self.destroy()

    def _cancel(self):
        self.destroy()