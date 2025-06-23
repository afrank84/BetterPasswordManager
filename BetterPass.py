import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Manager")

        self.vault = []
        self.current_type = 'login'
        self.password = ''

        self.setup_ui()

    def setup_ui(self):
        self.sidebar = tk.Frame(self.root, width=200, bg='#f0f0f0')
        self.sidebar.pack(side='left', fill='y')

        self.main = tk.Frame(self.root)
        self.main.pack(side='right', fill='both', expand=True)

        tk.Label(self.sidebar, text="🔐 Vault", font=('Arial', 12, 'bold')).pack(pady=10)
        for label, type_ in [("Login", 'login'), ("Wi-Fi", 'wifi'), ("PAT Token", 'pat_token'),
                             ("SSH Key", 'ssh_key'), ("Software Key", 'software_key')]:

            b = tk.Button(self.sidebar, text=label, anchor='w', command=lambda t=type_: self.change_type(t))
            b.pack(fill='x')

        self.password_entry = tk.Entry(self.sidebar, show='*')
        self.password_entry.pack(pady=5)

        tk.Button(self.sidebar, text='New Vault', command=self.new_vault).pack(fill='x', pady=2)
        tk.Button(self.sidebar, text='Load Vault', command=self.load_vault).pack(fill='x', pady=2)
        tk.Button(self.sidebar, text='Save Vault', command=self.save_vault).pack(fill='x', pady=2)
        tk.Button(self.sidebar, text='Export Plain', command=self.export_plain).pack(fill='x', pady=2)

        self.title_label = tk.Label(self.main, text='', font=('Arial', 14))
        self.title_label.pack(pady=5)

        self.tree = ttk.Treeview(self.main, columns=(), show='headings')
        self.tree.pack(fill='both', expand=True)

        tk.Button(self.main, text='Add Entry', command=self.add_entry).pack(pady=5)

        self.change_type('login')

    def change_type(self, entry_type):
        self.current_type = entry_type
        self.title_label.config(text=f"{self.current_type.title()} Entries")
        self.render_table()

    def icon(self, t):
        return {'login': '🔑', 'wifi': '📶', 'pat_token': '🧩', 'ssh_key': '🖥️', 'software_key': '📝'}.get(t, '🔐')

    def render_table(self):
        self.tree.delete(*self.tree.get_children())
        columns = []
        if self.current_type == 'login':
            columns = ['Site', 'Username', 'Password']
        elif self.current_type == 'wifi':
            columns = ['Label', 'SSID', 'Password']
        elif self.current_type == 'pat_token':
            columns = ['Label', 'Token']
        elif self.current_type == 'ssh_key':
            columns = ['Label', 'Username', 'Host']
        elif self.current_type == 'software_key':
            columns = ['Label', 'Product', 'License Key']

        self.tree.config(columns=columns)
        for col in columns:
            self.tree.heading(col, text=col)

        for entry in filter(lambda e: e['type'] == self.current_type, self.vault):
            row = []
            for col in columns:
                val = entry.get(col.lower().replace(' ', '')) or entry.get(col.lower())
                row.append(val if val else '')
            self.tree.insert('', 'end', values=row)

    def add_entry(self):
        entry = {'type': self.current_type}
        fields = []
        if self.current_type == 'login':
            fields = ['site', 'username', 'password']
        elif self.current_type == 'wifi':
            fields = ['label', 'ssid', 'password']
        elif self.current_type == 'pat_token':
            fields = ['label', 'token']
        elif self.current_type == 'ssh_key':
            fields = ['label', 'username', 'host', 'privateKey']
        elif self.current_type == 'software_key':
            fields = ['label', 'product', 'licenseKey', 'notes']

        for f in fields:
            val = simpledialog.askstring("Input", f.capitalize())
            if val is None:
                return
            entry[f] = val
        self.vault.append(entry)
        self.render_table()

    def save_vault(self):
        if not self.password_entry.get():
            return messagebox.showerror("Error", "Enter a password")
        data = json.dumps(self.vault).encode()
        salt = os.urandom(16)
        iv = os.urandom(12)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        key = kdf.derive(self.password_entry.get().encode())
        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(iv, data, None)
        blob = salt + iv + encrypted
        path = filedialog.asksaveasfilename(defaultextension=".enc")
        if path:
            with open(path, 'wb') as f:
                f.write(blob)

    def load_vault(self):
        path = filedialog.askopenfilename(filetypes=[("Encrypted Vault", "*.enc")])
        if not path:
            return
        with open(path, 'rb') as f:
            blob = f.read()
        salt, iv, data = blob[:16], blob[16:28], blob[28:]
        password = self.password_entry.get().encode()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        try:
            key = kdf.derive(password)
            aesgcm = AESGCM(key)
            decrypted = aesgcm.decrypt(iv, data, None)
            self.vault = json.loads(decrypted)
            self.render_table()
        except Exception:
            messagebox.showerror("Error", "Decryption failed")

    def new_vault(self):
        if not self.password_entry.get():
            return messagebox.showerror("Error", "Enter a password")
        if messagebox.askyesno("Confirm", "Start a new vault? This will erase the current vault in memory."):
            self.vault = []
            self.change_type('login')

    def export_plain(self):
        if messagebox.askyesno("Export", "Export as plain readable JSON?"):
            path = filedialog.asksaveasfilename(defaultextension=".json")
            if path:
                with open(path, 'w') as f:
                    json.dump(self.vault, f, indent=2)

if __name__ == '__main__':
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
