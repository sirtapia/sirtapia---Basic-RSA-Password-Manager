import tkinter as tk
import os

#Utility to center popup
def _center_over_parent(popup, parent, w, h):
    """Center popup over parent if possible, otherwise on screen."""
    try:
        parent.update_idletasks()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        x = px + max(0, (pw - w)//2)
        y = py + max(0, (ph - h)//2)
    except Exception:
        sw, sh = popup.winfo_screenwidth(), popup.winfo_screenheight()
        x = (sw - w)//2
        y = (sh - h)//2
    popup.geometry(f"{w}x{h}+{x}+{y}")


#Utility to set icon safely
def _set_icon(popup):
    """Try to apply icon.ico if available."""
    icon_path = os.path.join(os.path.dirname(__file__), "icon.ico")
    if os.path.exists(icon_path):
        try:
            popup.iconbitmap(icon_path)
        except Exception:
            pass


def customInput(parent, title, prompt, hide_input=False):
    """Custom themed input popup with a scrollable prompt and fixed input bar."""
    if parent is None:
        raise ValueError("customInput requires a parent window; pass the main root window.")

    popup = tk.Toplevel(parent)
    popup.transient(parent)
    popup.grab_set()
    popup.title(title)
    popup.configure(bg="#70552B")
    popup.resizable(False, False)

    #Apply custom icon
    _set_icon(popup)

    #header 
    header = tk.Frame(popup, bg="#4A3B20")
    header.pack(fill="x")
    tk.Label(header, text=title, bg="#4A3B20", fg="white",
             font=("Helvetica", 10, "bold")).pack(side="left", padx=10, pady=4)

    #Scrollable Area
    mid_frame = tk.Frame(popup, bg="#70552B", height=130)
    mid_frame.pack(fill="both", expand=True, padx=8, pady=(6, 0))
    mid_frame.pack_propagate(False)

    canvas = tk.Canvas(mid_frame, bg="#70552B", highlightthickness=0, bd=0)
    vsb = tk.Scrollbar(mid_frame, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    scroll_frame = tk.Frame(canvas, bg="#70552B")
    canvas.create_window((0, 0), window=scroll_frame, anchor="nw")

    def _on_frame_config(event):
        canvas.configure(scrollregion=canvas.bbox("all"))
    scroll_frame.bind("<Configure>", _on_frame_config)

    def _on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    canvas.bind_all("<MouseWheel>", _on_mousewheel)

    #Prompt label
    tk.Label(scroll_frame, text=prompt, bg="#70552B", fg="white",
             font=("Helvetica", 12), wraplength=340, justify="left").pack(
                 anchor="w", pady=(8, 8), padx=6)

    # Bottom Entry Bar 
    bottom = tk.Frame(popup, bg="#4A3B20")
    bottom.pack(fill="x", side="bottom")

    entry = tk.Entry(bottom, font=("Helvetica", 12),
                     show="*" if hide_input else "")
    entry.pack(side="left", padx=10, pady=8, expand=True, fill="x")
    entry.focus_set()

    result = {"value": None}

    def submit(event=None):
        result["value"] = entry.get()
        popup.destroy()

    tk.Button(
        bottom, text="Submit", command=submit,
        bg="#322611", fg="white", font=("Helvetica", 11, "bold"),
        bd=0, relief="flat", activebackground="#4A3B20",
        activeforeground="white", cursor="hand2"
    ).pack(side="right", padx=10, pady=8)

    entry.bind("<Return>", submit)

    #Window Geometry 
    popup.update_idletasks()
    w, h = 380, 260
    _center_over_parent(popup, parent, w, h)

    parent.wait_window(popup)
    return result["value"]


def customMessage(parent, title, message):
    """Custom themed message box (OK)."""
    if parent is None:
        raise ValueError("customMessage requires a parent window; pass the main root window.")

    popup = tk.Toplevel(parent)
    popup.transient(parent)
    popup.grab_set()
    popup.title(title)
    popup.configure(bg="#70552B")
    popup.resizable(False, False)

    #apply custom icon
    _set_icon(popup)

    header = tk.Frame(popup, bg="#4A3B20")
    header.pack(fill="x")
    tk.Label(header, text=title, bg="#4A3B20", fg="white",
             font=("Helvetica", 10, "bold")).pack(side="left", padx=10, pady=4)

    frame = tk.Frame(popup, bg="#70552B")
    frame.pack(fill="both", expand=True, padx=12, pady=8)
    tk.Label(frame, text=message, bg="#70552B", fg="white",
             font=("Helvetica", 12), wraplength=340, justify="left").pack(pady=(6, 8))

    ok_btn = tk.Button(
        frame, text="OK", command=popup.destroy,
        bg="#322611", fg="white", font=("Helvetica", 11, "bold"),
        bd=0, relief="flat", activebackground="#4A3B20", activeforeground="white",
        cursor="hand2"
    )
    ok_btn.pack(pady=(4, 10))
    ok_btn.focus_set()
    popup.bind("<Return>", lambda e: popup.destroy())

    popup.update_idletasks()
    _center_over_parent(popup, parent, 360, 180)
    parent.wait_window(popup)

