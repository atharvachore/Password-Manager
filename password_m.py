import tkinter as tk
import hashlib
import pyperclip
import string
import random


class PasswordManager:
    def __init__(self, master_password):
        self.master_password = hashlib.sha256(master_password.encode()).hexdigest()
        self.passwords = {}

    def add_password(self, website, username, password):
        website_hash = hashlib.sha256(website.encode()).hexdigest()
        username_hash = hashlib.sha256(username.encode()).hexdigest()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.passwords[website_hash] = (username_hash, password_hash)

    def get_password(self, website, clipboard=False):
        website_hash = hashlib.sha256(website.encode()).hexdigest()
        if website_hash in self.passwords:
            username_hash, password_hash = self.passwords[website_hash]
            username = self.decrypt(username_hash)
            password = self.decrypt(password_hash)
            if clipboard:
                pyperclip.copy(password)
            return f"Username: {username}\nPassword: {password}"
        else:
            return "No password found for this website."

    def generate_password(self, length=8):
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(chars) for i in range(length))
        return password

    def encrypt(self, text):
        return text[::-1]

    def decrypt(self, text):
        return text[::-1]


class PasswordManagerGUI:
    def __init__(self):
        self.password_manager = None
        self.master_password = ""
        self.create_login_gui()

    def create_login_gui(self):
        self.login_window = tk.Tk()
        self.login_window.title("Password Manager")
        self.login_label = tk.Label(self.login_window, text="Enter Master Password:")
        self.login_label.pack()
        self.login_entry = tk.Entry(self.login_window, show="*")
        self.login_entry.pack()
        self.login_button = tk.Button(self.login_window, text="Login", command=self.login)
        self.login_button.pack()
        self.login_window.mainloop()

    def create_main_gui(self):
        self.main_window = tk.Tk()
        self.main_window.title("Password Manager")
        self.generate_label = tk.Label(self.main_window, text="Generate Password:")
        self.generate_label.pack()
        self.generate_button = tk.Button(self.main_window, text="Generate", command=self.generate_password_gui)
        self.generate_button.pack()
        self.website_label = tk.Label(self.main_window, text="Website:")
        self.website_label.pack()
        self.website_entry = tk.Entry(self.main_window)
        self.website_entry.pack()
        self.username_label = tk.Label(self.main_window, text="Username:")
        self.username_label.pack()
        self.username_entry = tk.Entry(self.main_window)
        self.username_entry.pack()
        self.password_label = tk.Label(self.main_window, text="Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(self.main_window, show="*")
        self.password_entry.pack()
        self.save_button = tk.Button(self.main_window, text="Save", command=self.save_password_gui)
        self.save_button.pack()
        self.get_label = tk.Label(self.main_window, text="Get Password:")
        self.get_label.pack()
        self.get_button = tk.Button(self.main_window, text="Get", command=self.get_password_gui)
        self.get_button.pack()
        self.copy_button = tk.Button(self.main_window, text="Copy", command=self.copy_password_gui)
        self.copy_button.pack()
        self.main_window.protocol("WM_DELETE_WINDOW", self.quit)

    class PasswordManagerGUI:
        def __init__(self):
            self.password_manager = None
            self.master_password = ""
            self.create_login_gui()

        def create_login_gui(self):
            self.login_window = tk.Tk()
            self.login_window.title("Password Manager")
            self.login_label = tk.Label(self.login_window, text="Enter Master Password:")
            self.login_label.pack()
            self.login_entry = tk.Entry(self.login_window, show="*")
            self.login_entry.pack()
            self.login_button = tk.Button(self.login_window, text="Login", command=self.login)
            self.login_button.pack()
            self.login_window.mainloop()

        def create_main_gui(self):
            self.main_window = tk.Tk()
            self.main_window.title("Password Manager")
            self.generate_label = tk.Label(self.main_window, text="Generate Password:")
            self.generate_label.pack()
            self.generate_button = tk.Button(self.main_window, text="Generate", command=self.generate_password_gui)
            self.generate_button.pack()
            self.website_label = tk.Label(self.main_window, text="Website:")
            self.website_label.pack()
            self.website_entry = tk.Entry(self.main_window)
            self.website_entry.pack()
            self.username_label = tk.Label(self.main_window, text="Username:")
            self.username_label.pack()
            self.username_entry = tk.Entry(self.main_window)
            self.username_entry.pack()
            self.password_label = tk.Label(self.main_window, text="Password:")
            self.password_label.pack()
            self.password_entry = tk.Entry(self.main_window, show="*")
            self.password_entry.pack()
            self.save_button = tk.Button(self.main_window, text="Save", command=self.save_password_gui)
            self.save_button.pack()
            self.get_label = tk.Label(self.main_window, text="Get Password:")
            self.get_label.pack()
            self.get_button = tk.Button(self.main_window, text="Get", command=self.get_password_gui)
            self.get_button.pack()
            self.copy_button = tk.Button(self.main_window, text="Copy", command=self.copy_password_gui)
            self.copy_button.pack()
            self.main_window.protocol("WM_DELETE_WINDOW", self.quit)

        def login(self):
            master_password = self.login_entry.get()
            self.password_manager = PasswordManager(master_password)
            if self.password_manager:
                self.master_password = master_password
                self.login_window.destroy()
                self.create_main_gui()

        def generate_password_gui(self):
            password = self.password_manager.generate_password()
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, password)

        def save_password_gui(self):
            website = self.website_entry.get()
            username = self.username_entry.get()
            password = self.password_entry.get()
            self.password_manager.add_password(website, username, password)
            self.website_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)

        def get_password_gui(self):
            website = self.website_entry.get()
            password = self.password_manager.get_password(website, clipboard=False)
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, password)

        def copy_password_gui(self):
            website = self.website_entry.get()
            password = self.password_manager.get_password(website, clipboard=True)

        def quit(self):
            self.main_window.destroy()

    if __name__ == "__main__":
        gui = PasswordManagerGUI()

