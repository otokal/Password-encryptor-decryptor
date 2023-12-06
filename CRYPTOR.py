import tkinter as tk
from cryptography.fernet import Fernet

class MyWindow(tk.Tk):
    def __init__(self):
        super().__init__()

        # Frame params
        self.title("Password Locker")
        self.geometry("400x300")
        self.frame = tk.Frame(self)
        self.frame.pack(expand=True)
        self.update()
        self.frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Create buttons
        self.button1 = tk.Button(self.frame, text="ENCRYPT", width=10, command=self.open_window1)
        self.button1.grid(row=0, column=0, pady=10)
        self.button2 = tk.Button(self.frame, text="DECRYPT", width=10, command=self.open_window2)
        self.button2.grid(row=2, column=0, pady=10)

        self.label_or = tk.Label(self.frame, text="OR")
        self.label_or.grid(row=1, column=0, pady=10)
    # Functions Window 1
    def open_window1(self):
        self.window1 = tk.Toplevel(self)
        self.window1.title("ENCRYPTOR")
        self.window1.geometry("400x300")

        # Generate Key button and text box
        generate_key_button = tk.Button(self.window1, text="Generate Key", width=15, command=self.generate_key)
        generate_key_button.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)

        self.key_entry = tk.Entry(self.window1, width=30)
        self.key_entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.E)

        # Encrypt button, password text box, and encrypted password text box
        encrypt_button = tk.Button(self.window1, text="Encrypt", width=15, command=self.encrypt_password)
        encrypt_button.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)

        self.password_entry = tk.Entry(self.window1, width=30)
        self.password_entry.grid(row=1, column=1, padx=10, pady=10, sticky=tk.E)

        self.encrypted_password_entry = tk.Entry(self.window1, width=30)
        self.encrypted_password_entry.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def generate_key(self):
        key = Fernet.generate_key()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(tk.END, key.decode())

    def encrypt_password(self):
        password = self.password_entry.get()
        key = self.key_entry.get()
        f = Fernet(key.encode())
        encrypted_password = f.encrypt(password.encode())
        self.encrypted_password_entry.delete(0, tk.END)
        self.encrypted_password_entry.insert(tk.END, encrypted_password.decode())

    # Functions Window 2
    def open_window2(self):
        self.window2 = tk.Toplevel(self)
        self.window2.title("DECRYPTOR")
        self.window2.geometry("400x300")

        # Create Secret key params
        enter_key_label = tk.Label(self.window2, text="Enter Secret Key:")
        enter_key_label.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)

        self.secret_key_entry = tk.Entry(self.window2, width=30)
        self.secret_key_entry.grid(row=0, column=1, padx=10, pady=10)

        encrypted_password_label = tk.Label(self.window2, text="Encrypted Password:")
        encrypted_password_label.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)

        self.encrypted_password_entry2 = tk.Entry(self.window2, width=30)
        self.encrypted_password_entry2.grid(row=1, column=1, padx=10, pady=10)

        # Create Decrypt params
        decrypt_button = tk.Button(self.window2, text="Decrypt", width=15, command=self.decrypt_password)
        decrypt_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

        decrypted_password_label = tk.Label(self.window2, text="Decrypted Password:")
        decrypted_password_label.grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)

        self.decrypted_password_entry = tk.Entry
        self.decrypted_password_entry = tk.Entry(self.window2, width=30)
        self.decrypted_password_entry.grid(row=3, column=1, padx=10, pady=10)

    def decrypt_password(self):
        encrypted_password = self.encrypted_password_entry2.get()
        key = self.secret_key_entry.get()
        f = Fernet(key.encode())
        decrypted_password = f.decrypt(encrypted_password.encode())
        self.decrypted_password_entry.delete(0, tk.END)
        self.decrypted_password_entry.insert(tk.END, decrypted_password.decode())

window = MyWindow()

window.mainloop()
