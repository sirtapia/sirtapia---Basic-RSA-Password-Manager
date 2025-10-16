import tkinter as tk
from tkinter import messagebox
import main  # import your main.py module
from titlebar import createCustomTitleBar
from popup import customInput, customMessage
import ctypes
import os

# Global reference for the real application root window
root = None



def loginScreen():
    # ogin window is temporary; we'll destroy it and create MAIN root afterwards
    loginWin = tk.Tk()
    loginWin.title("Login - RSA Password Manager")
    loginWin.geometry("400x200")
    loginWin.configure(bg="#70552B")

    # custom titlebar for the login window (works but we destroy loginWin later)
    createCustomTitleBar(loginWin, "Login - RSA Password Manager")

    tk.Label(loginWin, text="Enter Master Password",
             font=("Helvetica", 16), fg="white", bg="#70552B").pack(pady=20)
    pwdEntry = tk.Entry(loginWin, show="*", font=("Helvetica", 12))
    pwdEntry.pack(pady=5)
    pwdEntry.focus_set()

    def attemptLogin(event=None):
        password = pwdEntry.get()
        if not os.path.exists("master.hash"):
            main.masterPassword = password
            hashed = main.hashlib.sha256(password.encode()).hexdigest()
            with open("master.hash", "w") as f:
                f.write(hashed)
            # show welcome message as a custom popup
            customMessage(loginWin, "Welcome", "Master password created!")
            main.ensureKeys(password)
            # destroy login and proceed to main app
            loginWin.destroy()
            main.loadData()
            mainMenu()   # creates new APP_ROOT and mainloop

        else:
            with open("master.hash", "r") as f:
                savedHash = f.read()
            if main.hashlib.sha256(password.encode()).hexdigest() == savedHash:
                main.masterPassword = password
                customMessage(loginWin, "Welcome", "Login successful!")
                main.ensureKeys(password)
                loginWin.destroy()
                main.loadData()
                mainMenu()
            else:
                customMessage(loginWin, "Error", "Login attempt unsuccessful")

    loginBtn = tk.Button(
        loginWin,
        text="Login",
        command=attemptLogin,
        font=("Helvetica", 14),
        fg="white",
        bg="#322611",
        activebackground="#4A3B20",
        activeforeground="white",
        relief="flat",
        width=12
    )
    loginBtn.pack(pady=15)

    loginWin.bind('<Return>', attemptLogin)
    loginWin.mainloop()




def addPasswordGUI():
    #ensure root exists
    global root
    web = customInput(root, "Website", "Enter website domain:")
    user = customInput(root, "Username", "Enter your username:")
    pwd = customInput(root, "Password", "Enter your password:", hide_input=True)

    if web and user and pwd:
        cipherb64 = main.encryptWithPublic(pwd)
        main.passwordData[web] = {"Username": user, "Password": cipherb64}
        main.saveData()
        customMessage(root, "Success", f"Password for {web} added!")
    else:
        customMessage(root, "Input Error", "All fields are required.")


def viewPasswordGUI():
    global root
    if not main.passwordData:
        customMessage(root, "No Data", "No passwords saved yet!")
        return

    webs = sorted(main.passwordData.keys())
    prompt = "Select website number:\n" + "\n".join([f"{i+1}. {w}" for i, w in enumerate(webs)])
    site_choice = customInput(root, "View Password", prompt)
    try:
        site_choice = int(site_choice)
    except (TypeError, ValueError):
        site_choice = None

    if site_choice and 1 <= site_choice <= len(webs):
        selectedSite = webs[site_choice - 1]
        details = main.passwordData[selectedSite]
        decryptedPwd = main.decryptWithPrivate(details["Password"], main.masterPassword)
        customMessage(root, f"{selectedSite}", f"Username: {details['Username']}\nPassword: {decryptedPwd}")
    else:
        customMessage(root, "Invalid Choice", "Please select a valid website number.")


def remPasswordGUI():
    global root
    if not main.passwordData:
        customMessage(root, "No Data", "No passwords saved yet!")
        return

    webs = sorted(main.passwordData.keys())
    prompt = "Select website number:\n" + "\n".join([f"{i+1}. {w}" for i, w in enumerate(webs)])
    site_choice = customInput(root, "Remove Password", prompt)
    try:
        site_choice = int(site_choice)
    except (TypeError, ValueError):
        site_choice = None

    if site_choice and 1 <= site_choice <= len(webs):
        selectedSite = webs[site_choice - 1]
        main.passwordData.pop(selectedSite)
        main.saveData()
        customMessage(root, "Removed", f"Password for {selectedSite} removed!")
    else:
        customMessage(root, "Invalid Choice", "Please select a valid website number.")


def updPasswordGUI():
    global root
    if not main.passwordData:
        customMessage(root, "No Data", "No passwords saved yet!")
        return

    webs = sorted(main.passwordData.keys())
    prompt = "Select website number:\n" + "\n".join([f"{i+1}. {w}" for i, w in enumerate(webs)])
    site_choice = customInput(root, "Update Password", prompt)
    try:
        site_choice = int(site_choice)
    except (TypeError, ValueError):
        site_choice = None

    if site_choice and 1 <= site_choice <= len(webs):
        selectedSite = webs[site_choice - 1]
        newPwd = customInput(root, "New Password", "Enter new password:", hide_input=True)
        if newPwd:
            cipherb64 = main.encryptWithPublic(newPwd)
            main.passwordData[selectedSite]["Password"] = cipherb64
            main.saveData()
            customMessage(root, "Updated", f"Password for {selectedSite} updated!")
        else:
            customMessage(root, "Input Error", "Password cannot be empty.")
    else:
        customMessage(root, "Invalid Choice", "Please select a valid website number.")


def searchPasswordGUI():
    global root
    if not main.passwordData:
        customMessage(root, "No Data", "No passwords saved yet!")
        return

    query = customInput(root, "Search", "Enter website name to search:")
    if query:
        matches = [w for w in main.passwordData if query.lower() in w.lower()]
        if not matches:
            customMessage(root, "No Match", "No websites found matching your query.")
            return
        prompt = "Matching websites:\n" + "\n".join([f"{i+1}. {w}" for i, w in enumerate(matches)])
        site_choice = customInput(root, "Select Website", prompt)
        try:
            site_choice = int(site_choice)
        except (TypeError, ValueError):
            site_choice = None

        if site_choice and 1 <= site_choice <= len(matches):
            selectedSite = matches[site_choice - 1]
            details = main.passwordData[selectedSite]
            decryptedPwd = main.decryptWithPrivate(details["Password"], main.masterPassword)
            customMessage(root, f"{selectedSite}", f"Username: {details['Username']}\nPassword: {decryptedPwd}")
        else:
            customMessage(root, "Invalid Choice", "Please select a valid website number.")


def genPasswordGUI():
    global root
    length_str = customInput(root, "Password Length", "Enter password length (5-25):")
    try:
        length = int(length_str) if length_str else None
    except ValueError:
        length = None

    if length:
        newPwd = main.generatePassword(length)
        customMessage(root, "Generated Password", f"Password: {newPwd}")
    else:
        customMessage(root, "Input Error", "Invalid length.")


def centerWindow(win, width, height):
    win.update_idletasks()
    screenWidth = win.winfo_screenwidth()
    screenHeight = win.winfo_screenheight()
    x = (screenWidth // 2) - (width // 2)
    y = (screenHeight // 2) - (height // 2)
    win.geometry(f"{width}x{height}+{x}+{y}")


def mainMenu():
    global root
    root = tk.Tk()
    createCustomTitleBar(root, "Main Menu - RSA Password Manager")
    root.title("Basic RSA Password Manager")
    centerWindow(root, 400, 450)
    root.configure(bg="#70552B")

    tk.Label(root, text="Basic RSA Password Manager",
             font=("Helvetica", 16), fg="white", bg="#70552B").pack(pady=10)

    buttonStyle = {"width": 25, "height": 2, "bg": "#322611", "fg": "white",
                   "font": ("Helvetica", 12, "bold"), "bd": 0, "relief": "flat",
                   "activebackground": "#4A3B20", "activeforeground": "white", "cursor": "hand2"}

    tk.Button(root, text="Add Password", command=addPasswordGUI, **buttonStyle).pack(pady=5)
    tk.Button(root, text="View Password", command=viewPasswordGUI, **buttonStyle).pack(pady=5)
    tk.Button(root, text="Remove Password", command=remPasswordGUI, **buttonStyle).pack(pady=5)
    tk.Button(root, text="Update Password", command=updPasswordGUI, **buttonStyle).pack(pady=5)
    tk.Button(root, text="Search Password", command=searchPasswordGUI, **buttonStyle).pack(pady=5)
    tk.Button(root, text="Generate Password", command=genPasswordGUI, **buttonStyle).pack(pady=5)

    root.mainloop()


#make tkinter window show up in the task bar (Windows)
myappid = 'RSA.PasswordManager'
ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

if __name__ == "__main__":
    if hasattr(main, 'masterPassword'):
        main.loadData()
    else:
        main.masterPassword = None
    loginScreen()
