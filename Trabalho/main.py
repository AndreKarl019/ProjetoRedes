import tkinter as tk

from interface.main_window import SecurePeerApp


def main():
    root = tk.Tk()
    app = SecurePeerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()