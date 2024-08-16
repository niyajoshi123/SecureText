import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import os

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptography Program")

        self.algo_label = tk.Label(root, text="Choose Cryptographic Algorithm:")
        self.algo_label.pack()

        self.aes_button = tk.Button(root, text="AES", command=self.open_aes_form)
        self.aes_button.pack(pady=5)

        self.rsa_button = tk.Button(root, text="RSA", command=self.open_rsa_form)
        self.rsa_button.pack(pady=5)

        self.hash_button = tk.Button(root, text="Hash", command=self.open_hash_form)
        self.hash_button.pack(pady=5)

        # Fixed AES key
        self.fixed_aes_key = b"abcdefghijklmnop"  # 16-byte key

        # RSA keys (fixed for simplicity)
        self.rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.rsa_public_key = self.rsa_private_key.public_key()

    def open_aes_form(self):
        aes_window = tk.Toplevel(self.root)
        aes_window.title("AES Encryption/Decryption")

        tk.Label(aes_window, text="Enter Message:").pack()
        aes_message_entry = tk.Entry(aes_window, width=50)
        aes_message_entry.pack()

        tk.Label(aes_window, text="Enter AES Key:").pack()
        aes_key_entry = tk.Entry(aes_window, width=50, show="*")  # Masked input
        aes_key_entry.pack()

        result_label = tk.Label(aes_window, text="")
        result_label.pack()

        def aes_encrypt():
            key = aes_key_entry.get().encode()
            if key != self.fixed_aes_key:
                messagebox.showerror("Error", "Invalid key.")
                return

            message = aes_message_entry.get().encode()
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_message = iv + encryptor.update(message) + encryptor.finalize()
            result_label.config(text="Encrypted Message:")
            result_text.config(state=tk.NORMAL)  # Enable editing for result text
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, base64.b64encode(encrypted_message).decode())
            result_text.config(state=tk.DISABLED)  # Disable editing

        def aes_decrypt():
            key = aes_key_entry.get().encode()
            if key != self.fixed_aes_key:
                messagebox.showerror("Error", "Invalid key.")
                return

            encrypted_message = base64.b64decode(aes_message_entry.get().encode())
            iv = encrypted_message[:16]
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
            result_label.config(text="Decrypted Message:")
            result_text.config(state=tk.NORMAL)  # Enable editing for result text
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, decrypted_message.decode())
            result_text.config(state=tk.DISABLED)  # Disable editing

        result_text = tk.Text(aes_window, width=50, height=4, state=tk.DISABLED)  # Read-only text
        result_text.pack()

        tk.Button(aes_window, text="Encrypt", command=aes_encrypt).pack(pady=5)
        tk.Button(aes_window, text="Decrypt", command=aes_decrypt).pack(pady=5)

    def open_rsa_form(self):
        rsa_window = tk.Toplevel(self.root)
        rsa_window.title("RSA Encryption/Decryption")

        tk.Label(rsa_window, text="Enter Message:").pack()
        rsa_message_entry = tk.Entry(rsa_window, width=50)
        rsa_message_entry.pack()

        result_label = tk.Label(rsa_window, text="")
        result_label.pack()

        def rsa_encrypt():
            public_key = self.rsa_public_key
            message = rsa_message_entry.get().encode()

            try:
                encrypted_message = public_key.encrypt(
                    message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                result_label.config(text="Encrypted Message:")
                result_text.config(state=tk.NORMAL)  # Enable editing for result text
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, base64.b64encode(encrypted_message).decode())
                result_text.config(state=tk.DISABLED)  # Disable editing
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {str(e)}")

        def rsa_decrypt():
            private_key = self.rsa_private_key
            encrypted_message = base64.b64decode(rsa_message_entry.get().encode())

            try:
                decrypted_message = private_key.decrypt(
                    encrypted_message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                result_label.config(text="Decrypted Message:")
                result_text.config(state=tk.NORMAL)  # Enable editing for result text
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, decrypted_message.decode())
                result_text.config(state=tk.DISABLED)  # Disable editing
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")

        result_text = tk.Text(rsa_window, width=50, height=4, state=tk.DISABLED)  # Read-only text
        result_text.pack()

        tk.Button(rsa_window, text="Encrypt", command=rsa_encrypt).pack(pady=5)
        tk.Button(rsa_window, text="Decrypt", command=rsa_decrypt).pack(pady=5)

    def open_hash_form(self):
        hash_window = tk.Toplevel(self.root)
        hash_window.title("Hashing")

        tk.Label(hash_window, text="Enter Message:").pack()
        hash_message_entry = tk.Entry(hash_window, width=50)
        hash_message_entry.pack()

        result_label = tk.Label(hash_window, text="")
        result_label.pack()

        def hash_message():
            message = hash_message_entry.get().encode()

            hash_obj = hashlib.sha256()
            hash_obj.update(message)
            hashed_message = hash_obj.hexdigest()
            result_label.config(text="Hashed Message:")
            result_text.config(state=tk.NORMAL)  # Enable editing for result text
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, hashed_message)
            result_text.config(state=tk.DISABLED)  # Disable editing

        result_text = tk.Text(hash_window, width=50, height=4, state=tk.DISABLED)  # Read-only text
        result_text.pack()

        tk.Button(hash_window, text="Hash", command=hash_message).pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
