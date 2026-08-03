import tkinter as tk

from gui.main_window import PacketSnifferApp


def main():

    root = tk.Tk()

    PacketSnifferApp(root)

    root.mainloop()


if __name__ == "__main__":
    main()