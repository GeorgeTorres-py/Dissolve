import gnupg
import sqlite3
import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext
import os
import threading
import time

class SecureMessenger:
    def __init__(self):
        self.gpg = gnupg.GPG(gnupghome='gpg_home')
        self.db_conn = sqlite3.connect('messenger.db', check_same_thread=False)
        self.setup_database()
        self.current_user = None
        self.setup_gui()

    def setup_database(self):
        cursor = self.db_conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                public_key TEXT,
                private_key TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                sender TEXT,
                recipient TEXT,
                message TEXT,
                timestamp DATETIME,
                read INTEGER DEFAULT 0
            )
        ''')
        self.db_conn.commit()

    def generate_key_pair(self, username):
        input_data = self.gpg.gen_key_input(
            key_type="RSA",
            key_length=2048,
            name_real=username,
            name_email=f"{username}@secure.msg"
        )
        key = self.gpg.gen_key(input_data)
        public_key = self.gpg.export_keys(str(key))
        private_key = self.gpg.export_keys(str(key), True)
        return public_key, private_key

    def register_user(self):
        username = self.username_entry.get()
        if not username:
            return
        
        public_key, private_key = self.generate_key_pair(username)
        cursor = self.db_conn.cursor()
        cursor.execute('INSERT INTO users VALUES (?, ?, ?)',
                      (username, public_key, private_key))
        self.db_conn.commit()
        self.current_user = username
        self.show_messenger()

    def encrypt_message(self, recipient, message):
        cursor = self.db_conn.cursor()
        cursor.execute('SELECT public_key FROM users WHERE username = ?',
                      (recipient,))
        recipient_key = cursor.fetchone()[0]
        encrypted = self.gpg.encrypt(message, recipient_key)
        return str(encrypted)

    def decrypt_message(self, message):
        decrypted = self.gpg.decrypt(message)
        return str(decrypted)

    def send_message(self):
        recipient = self.recipient_entry.get()
        message = self.message_entry.get("1.0", tk.END).strip()
        
        if not recipient or not message:
            return
            
        encrypted_message = self.encrypt_message(recipient, message)
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO messages (sender, recipient, message, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (self.current_user, recipient, encrypted_message,
              datetime.datetime.now()))
        self.db_conn.commit()
        self.message_entry.delete("1.0", tk.END)
        self.update_messages()

    def check_new_messages(self):
        while True:
            if self.current_user:
                cursor = self.db_conn.cursor()
                cursor.execute('''
                    SELECT id, sender, message, timestamp, read
                    FROM messages 
                    WHERE recipient = ? AND read = 0
                    ORDER BY timestamp
                ''', (self.current_user,))
                
                new_messages = cursor.fetchall()
                for msg in new_messages:
                    msg_id, sender, encrypted_message, timestamp, read = msg
                    decrypted_message = self.decrypt_message(encrypted_message)
                    self.messages_text.insert(tk.END, 
                        f"\nFrom {sender} at {timestamp}:\n{decrypted_message}\n")
                    
                    # Mark message as read
                    cursor.execute('''
                        UPDATE messages SET read = 1 
                        WHERE id = ?
                    ''', (msg_id,))
                    
                    # Delete message after reading
                    cursor.execute('DELETE FROM messages WHERE id = ?', (msg_id,))
                    
                self.db_conn.commit()
            time.sleep(1)

    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title("Secure Messenger")
        
        # Login Frame
        self.login_frame = ttk.Frame(self.root, padding="10")
        self.login_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(self.login_frame, text="Username:").grid(row=0, column=0)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1)
        ttk.Button(self.login_frame, text="Register/Login",
                  command=self.register_user).grid(row=1, column=0, columnspan=2)

        # Messenger Frame
        self.messenger_frame = ttk.Frame(self.root, padding="10")
        
        ttk.Label(self.messenger_frame, text="Recipient:").grid(row=0, column=0)
        self.recipient_entry = ttk.Entry(self.messenger_frame)
        self.recipient_entry.grid(row=0, column=1)
        
        self.messages_text = scrolledtext.ScrolledText(self.messenger_frame,
                                                     width=50, height=20)
        self.messages_text.grid(row=1, column=0, columnspan=2)
        
        self.message_entry = scrolledtext.ScrolledText(self.messenger_frame,
                                                     width=50, height=3)
        self.message_entry.grid(row=2, column=0, columnspan=2)
        
        ttk.Button(self.messenger_frame, text="Send",
                  command=self.send_message).grid(row=3, column=0, columnspan=2)

        # Start message checking thread
        threading.Thread(target=self.check_new_messages, daemon=True).start()

    def show_messenger(self):
        self.login_frame.grid_remove()
        self.messenger_frame.grid(row=0, column=0,
                                sticky=(tk.W, tk.E, tk.N, tk.S))

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    if not os.path.exists('gpg_home'):
        os.makedirs('gpg_home')
    app = SecureMessenger()
    app.run()
