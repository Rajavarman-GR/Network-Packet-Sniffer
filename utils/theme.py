"""Centralized semantic design tokens and Tk/ttk theme application."""

TOKENS = {
    "dark": {
        "background": "#111827", "surface": "#1F2937", "elevated": "#273449",
        "border": "#374151", "text": "#F3F4F6", "muted": "#9CA3AF",
        "accent": "#60A5FA", "success": "#34D399", "warning": "#FBBF24",
        "danger": "#F87171", "info": "#38BDF8", "table": "#172033",
        "navigation": "#182234", "selection": "#1D4ED8", "disabled": "#6B7280",
    },
    "light": {
        "background": "#F3F4F6", "surface": "#FFFFFF", "elevated": "#F9FAFB",
        "border": "#D1D5DB", "text": "#111827", "muted": "#4B5563",
        "accent": "#2563EB", "success": "#047857", "warning": "#92400E",
        "danger": "#B91C1C", "info": "#0369A1", "table": "#FFFFFF",
        "navigation": "#E5E7EB", "selection": "#BFDBFE", "disabled": "#9CA3AF",
    },
}
FONT_FAMILY = "Segoe UI"
SIZES = {"space_xs": 4, "space_sm": 8, "space_md": 12, "space_lg": 20,
         "radius_sm": 4, "control_height": 30, "font_small": 9, "font_body": 10,
         "font_section": 12, "font_subtitle": 14, "font_metric": 15, "font_title": 17,
         "tab_pad_y": 7}


def get_tokens(theme="dark"):
    """Return fresh tokens while keeping legacy dark/light settings compatible."""
    return dict(TOKENS.get(theme, TOKENS["dark"]))


def apply_tk_theme(root, theme="dark"):
    """Apply semantic colors to ttk and classic Tk descendants, including dialogs."""
    import tkinter as tk
    from tkinter import ttk

    colors = get_tokens(theme)
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("TFrame", background=colors["surface"])
    style.configure("TLabel", background=colors["surface"], foreground=colors["text"],
                    font=(FONT_FAMILY, SIZES["font_body"]))
    style.configure("TLabelframe", background=colors["surface"], foreground=colors["text"], bordercolor=colors["border"])
    style.configure("TLabelframe.Label", background=colors["surface"], foreground=colors["text"])
    button_text = colors["background"] if theme == "dark" else "#FFFFFF"
    style.configure("TButton", background=colors["elevated"], foreground=colors["text"],
                     padding=(SIZES["space_md"], SIZES["space_xs"] + 2), bordercolor=colors["border"],
                     font=(FONT_FAMILY, SIZES["font_body"]))
    style.map("TButton", background=[("active", colors["selection"]), ("disabled", colors["surface"])],
              foreground=[("disabled", colors["disabled"])])
    style.configure("TEntry", fieldbackground=colors["table"], foreground=colors["text"], insertcolor=colors["text"])
    style.configure("TCheckbutton", background=colors["surface"], foreground=colors["text"],
                    font=(FONT_FAMILY, SIZES["font_body"]))
    style.configure("TCombobox", fieldbackground=colors["elevated"], background=colors["surface"], foreground=colors["text"], arrowcolor=colors["text"])
    style.map("TCombobox", fieldbackground=[("readonly", colors["elevated"])], foreground=[("readonly", colors["text"])])
    style.configure("TNotebook", background=colors["background"], borderwidth=0)
    style.configure("TNotebook.Tab", background=colors["surface"], foreground=colors["muted"],
                     padding=(SIZES["space_md"], SIZES["tab_pad_y"]),
                     font=(FONT_FAMILY, SIZES["font_body"]))
    style.map("TNotebook.Tab", background=[("selected", colors["elevated"])], foreground=[("selected", colors["text"])])
    style.configure("Treeview", background=colors["table"], foreground=colors["text"],
                     fieldbackground=colors["table"], rowheight=SIZES["control_height"], bordercolor=colors["border"])
    style.configure("Treeview.Heading", background=colors["elevated"], foreground=colors["text"], relief="flat",
                     font=(FONT_FAMILY, SIZES["font_body"], "bold"))
    style.map("Treeview", background=[("selected", colors["selection"])], foreground=[("selected", colors["text"])])
    style.configure("TScrollbar", background=colors["surface"], troughcolor=colors["background"], arrowcolor=colors["text"])

    def visit(widget):
        try:
            kind = widget.winfo_class()
            if kind in {"Tk", "Toplevel"}:
                widget.configure(background=colors["background"])
            elif kind in {"Frame", "Labelframe", "Panedwindow"}:
                widget.configure(background=colors["surface"])
            elif kind == "Label":
                widget.configure(background=colors["surface"], foreground=colors["text"])
            elif kind in {"Text", "Entry", "Listbox"}:
                widget.configure(background=colors["table"], foreground=colors["text"], insertbackground=colors["text"])
            elif kind == "Button":
                caption = str(widget.cget("text")).casefold()
                bg = colors["accent"]
                fg = button_text
                if "start" in caption:
                    bg = colors["success"]
                elif "stop" in caption or "cancel" in caption:
                    bg = colors["danger"]
                widget.configure(background=bg, foreground=fg, activebackground=colors["selection"], activeforeground=colors["text"],
                                 disabledforeground=colors["disabled"], relief="flat", highlightthickness=1,
                                 highlightbackground=colors["border"], highlightcolor=colors["accent"])
            elif kind == "Menu":
                widget.configure(background=colors["surface"], foreground=colors["text"], activebackground=colors["selection"], activeforeground=colors["text"])
        except (tk.TclError, AttributeError):
            pass
        for child in widget.winfo_children():
            visit(child)

    visit(root)
