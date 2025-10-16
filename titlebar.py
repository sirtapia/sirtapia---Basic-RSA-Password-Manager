import tkinter as tk
import ctypes
import os

def createCustomTitleBar(window, titleText="RSA Password Manager"):
    # Ensure Windows taskbar entry 
    myappid = 'RSA.PasswordManager'
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    except Exception:
        pass

    #Set app icon if available 
    icon_path = os.path.join(os.path.dirname(__file__), "icon.ico")
    if os.path.exists(icon_path):
        try:
            window.iconbitmap(icon_path)
        except Exception:
            pass

    #Make sure window shows in taskbar 
    hwnd = window.winfo_id()
    GWL_EXSTYLE = -20
    WS_EX_APPWINDOW = 0x00040000
    WS_EX_TOOLWINDOW = 0x00000080
    style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
    style = (style | WS_EX_APPWINDOW) & ~WS_EX_TOOLWINDOW
    ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style)

    # Remove default Windows title bar 
    window.overrideredirect(True)
    window.attributes('-toolwindow', False)
    window.update_idletasks()

    # Center window 
    x = (window.winfo_screenwidth() // 2) - (400 // 2)
    y = (window.winfo_screenheight() // 2) - (300 // 2)
    window.geometry(f"400x300+{x}+{y}")
    window.attributes("-alpha", 0.9999)

    # Custom title bar frame 
    titleFrame = tk.Frame(window, bg="#4A3B20", height=30)
    titleFrame.pack(fill="x", side="top")

    # Title text 
    titleLabel = tk.Label(
        titleFrame, text=titleText,
        bg="#4A3B20", fg="white",
        font=("Helvetica", 10, "bold")
    )
    titleLabel.pack(side="left", padx=10)

    #Close button only 
    def close():
        window.destroy()

    closeBtn = tk.Button(
        titleFrame, text="✕", bg="#4F0707", fg="white",
        bd=0, font=("Helvetica", 10, "bold"), command=close
    )
    closeBtn.pack(side="right", padx=5, pady=2)

    # Window dragging
    def startMove(event):
        window._dragx = event.x
        window._dragy = event.y

    def moveWindow(event):
        x = window.winfo_pointerx() - window._dragx
        y = window.winfo_pointery() - window._dragy
        window.geometry(f"+{x}+{y}")

    titleFrame.bind("<Button-1>", startMove)
    titleFrame.bind("<B1-Motion>", moveWindow)
    titleLabel.bind("<Button-1>", startMove)
    titleLabel.bind("<B1-Motion>", moveWindow)

