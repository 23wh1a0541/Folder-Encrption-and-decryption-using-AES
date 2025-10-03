import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from PIL import Image, ImageTk, ImageDraw
import os, webbrowser, tempfile, secrets, smtplib, zipfile
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import shutil
import time

# Background image path
BACKGROUND_PATH = r"C:\Users\tasle\project\siri1.jpg"

class FolderEncryptorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Folder Encryption & Decryption")
        self.root.state("zoomed")
        self.bg_label = None
        self.bg_photo = None
        self._set_background()
        self.root.bind("<Configure>", self._resize_bg)
        self._build_interface()

    # ------------------- BACKGROUND ------------------- #
    def _set_background(self):
        if os.path.exists(BACKGROUND_PATH):
            img = Image.open(BACKGROUND_PATH).convert("RGBA")
            win_w, win_h = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
            img = img.resize((win_w, win_h), Image.LANCZOS)
            self.bg_photo = ImageTk.PhotoImage(img)
            if not self.bg_label:
                self.bg_label = tk.Label(self.root, image=self.bg_photo)
                self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            else:
                self.bg_label.configure(image=self.bg_photo)
        else:
            self.root.configure(bg="#101010")

    def _resize_bg(self, event):
        if os.path.exists(BACKGROUND_PATH):
            img = Image.open(BACKGROUND_PATH).convert("RGBA")
            img = img.resize((event.width, event.height), Image.LANCZOS)
            self.bg_photo = ImageTk.PhotoImage(img)
            if self.bg_label:
                self.bg_label.configure(image=self.bg_photo)

    # ------------------- INTERFACE ------------------- #
    def _build_interface(self):
        # Project Info button
        top_frame = tk.Frame(self.root, bg="", padx=0, pady=8)
        top_frame.place(relx=0.5, rely=0.04, anchor="n")
        project_btn = tk.Button(
            top_frame,
            text="📘 Project Info",
            font=("Segoe UI", 12, "bold"),
            bg="#3a6ea5", fg="white", bd=0, relief="flat",
            activebackground="#558cc9", activeforeground="white",
            padx=14, pady=6,
            command=self.open_about
        )
        project_btn.pack()
        self._add_hover(project_btn, normal_bg="#3a6ea5", hover_bg="#558cc9")

        # Right-side panel
        panel_bg = "#1e1e1e"
        panel_border = "#3a6ea5"
        container = tk.Frame(
            self.root, bg=panel_bg, bd=0,
            highlightthickness=2, highlightbackground=panel_border,
            padx=16, pady=12
        )
        container.place(relx=0.75, rely=0.2, relwidth=0.35, relheight=0.6, anchor="n")

        title = tk.Label(container, text="Secure Folder Encryption", font=("Segoe UI", 16, "bold"),
                         fg="white", bg=panel_bg)
        title.pack(pady=(6,6))

        subtitle = tk.Label(container, text="AES-256-GCM • PBKDF2 • Secure Email Delivery",
                            font=("Segoe UI", 9), fg="#cccccc", bg=panel_bg)
        subtitle.pack(pady=(0,10))

        self._load_icon(container)

        # Buttons - BOTH ENCRYPT AND DECRYPT
        btn_frame = tk.Frame(container, bg=panel_bg)
        btn_frame.pack(pady=8)
        
        # Encrypt Button
        encrypt_btn = tk.Button(btn_frame, text="Encrypt Folder", font=("Segoe UI", 11, "bold"),
                                bg="#3a6ea5", fg="white", width=18, height=2,
                                command=self.encrypt_window)
        encrypt_btn.grid(row=0, column=0, padx=8, pady=6)
        self._add_hover(encrypt_btn, normal_bg="#3a6ea5", hover_bg="#558cc9")

        # Decrypt Button
        decrypt_btn = tk.Button(btn_frame, text="Decrypt Folder", font=("Segoe UI", 11, "bold"),
                                bg="#2a9d8f", fg="white", width=18, height=2,
                                command=self.decrypt_window)
        decrypt_btn.grid(row=1, column=0, padx=8, pady=6)
        self._add_hover(decrypt_btn, normal_bg="#2a9d8f", hover_bg="#45b7a8")

        foot = tk.Label(container, text="Tip: Use strong passphrases & test on copies.",
                        font=("Segoe UI", 8), fg="#aaaaaa", bg=panel_bg)
        foot.pack(side="bottom", pady=(8,2))

    # ------------------- ICON ------------------- #
    def _load_icon(self, parent):
        script_dir = os.path.dirname(__file__)
        for ext in ("png", "jpg", "jpeg", "ico"):
            icon_path = os.path.join(script_dir, f"image.{ext}")
            if os.path.exists(icon_path):
                img = Image.open(icon_path).convert("RGBA").resize((90,90), Image.LANCZOS)
                self.folder_icon = ImageTk.PhotoImage(img)
                tk.Label(parent, image=self.folder_icon, bg=parent["bg"], bd=0).pack(pady=5)
                return
        tk.Label(parent, text="🔒", font=("Segoe UI",48), fg="#3a6ea5", bg=parent["bg"]).pack(pady=5)

    # ------------------- HOVER ------------------- #
    def _add_hover(self, widget, normal_bg, hover_bg):
        widget.bind("<Enter>", lambda e: widget.config(bg=hover_bg))
        widget.bind("<Leave>", lambda e: widget.config(bg=normal_bg))

    # ------------------- PROJECT INFO ------------------- #
    def open_about(self):
        logo_path = r"C:/Users/tasle/project/logo.jpeg"
        circular_logo_path = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
        if os.path.exists(logo_path):
            img = Image.open(logo_path).convert("RGBA").resize((120,120))
            mask = Image.new('L', (120,120), 0)
            draw = ImageDraw.Draw(mask)
            draw.ellipse((0,0,120,120), fill=255)
            img.putalpha(mask)
            img.save(circular_logo_path)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Project Information</title>
<style>
body {{font-family: Arial, sans-serif; margin: 40px; background-color: #f9f9f9; color: #333;}}
h1 {{font-size: 28px; margin-top: 150px; margin-bottom: 10px;}}
p {{font-size: 16px; line-height: 1.6; margin-top: 20px;}}
table {{border-collapse: collapse; width: 70%; margin-top: 15px; background: #fff;}}
table, th, td {{border: 1px solid #ccc;}}
th, td {{padding: 10px; text-align: left;}}
th {{background: #f2f2f2; width: 200px;}}
.section-title {{margin-top: 30px; font-size: 20px; font-weight: bold;}}
.logo {{position: absolute; top: 20px; right: 40px; width: 120px; height: 120px; border-radius: 50%;}}
</style>
</head>
<body>
<img src="{circular_logo_path}" alt="Company Logo" class="logo">
<h1>Project Information</h1>
<p>This project was developed by <b>Siri,Tasleem,Bhavya,Manasa</b> as part of a 
<b>Cyber Security Internship</b>. This project is designed to 
<b>Secure the Organizations in Real World from Cyber Frauds performed by Hackers.</b></p>
<table>
<tr><th>Project Details</th><th>Value</th></tr>
<tr><td>Project Name</td><td>Folder Encryption & Decryption using AES</td></tr>
<tr><td>Project Description</td><td>Implementing Secured Encryption Standards for Folders which Contain Secured Data</td></tr>
<tr><td>Project Start Date</td><td>26-AUG-2025</td></tr>
<tr><td>Project End Date</td><td>10-OCT-2025</td></tr>
<tr><td>Project Status</td><td><b>Completed</b></td></tr>
</table>
<div class="section-title">Developer Details</div>
<table>
<tr><th>Name</th><td>E.SIRI</td></tr>
<tr><th>Employee ID</th><td>23WH1A0512</td></tr>
<tr><th>Email</th><td>23wh1a0512@bvrithyderabad.edu.in</td></tr>
<tr><th>Name</th><td>SK.TASLEEM</td></tr>
<tr><th>Employee ID</th><td>23WH1A0541</td></tr>
<tr><th>Email</th><td>23wh1a0541@bvrithyderabad.edu.in</td></tr>
<tr><th>Name</th><td>A.BHAVYA</td></tr>
<tr><th>Employee ID</th><td>23WH1A0581</td></tr>
<tr><th>Email</th><td>23wh1a0581@bvrithyderabad.edu.in</td></tr>
<tr><th>Name</th><td>MANASA</td></tr>
<tr><th>Employee ID</th><td>23WH1A0585</td></tr>
<tr><th>Email</th><td>23wh1a0585@bvrithyderabad.edu.in</td></tr>
</table>
<div class="section-title">Company Details</div>
<table>
<tr><th>Company</th><td>Supraja Technologies</td></tr>
<tr><th>Email</th><td>contact@suprajatechnologies.com</td></tr>
</table>
</body>
</html>"""
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode='w', encoding='utf-8')
        tmp_file.write(html_content)
        tmp_file.close()
        webbrowser.open(f"file://{tmp_file.name}")

    # ------------------- ENCRYPT WINDOW ------------------- #
    def encrypt_window(self):
        self.encrypt_win = tk.Toplevel(self.root)
        self.encrypt_win.title("Encrypt Folder")
        self.encrypt_win.geometry("600x520")
        self.encrypt_win.configure(bg="#f0f0f0")
        self.encrypt_win.resizable(False, False)
        
        # Center the window
        self.encrypt_win.transient(self.root)
        self.encrypt_win.grab_set()
        
        main_frame = tk.Frame(self.encrypt_win, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title = tk.Label(main_frame, text="Folder Encryption", font=("Segoe UI", 16, "bold"), 
                        bg="#f0f0f0", fg="#2c3e50")
        title.pack(pady=(0, 15))

        # Folder selection
        folder_frame = tk.Frame(main_frame, bg="#f0f0f0")
        folder_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(folder_frame, text="Select Folder to Encrypt:", bg="#f0f0f0", 
                font=("Segoe UI", 10)).pack(anchor="w")
        
        entry_frame = tk.Frame(folder_frame, bg="#f0f0f0")
        entry_frame.pack(fill=tk.X, pady=5)
        
        self.folder_entry = tk.Entry(entry_frame, width=50, font=("Segoe UI", 10))
        self.folder_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        browse_btn = tk.Button(entry_frame, text="Browse", command=self.browse_encrypt_folder, 
                              bg="#3a6ea5", fg="white", font=("Segoe UI", 9), width=10)
        browse_btn.pack(side=tk.RIGHT)
        self._add_hover(browse_btn, normal_bg="#3a6ea5", hover_bg="#558cc9")

        # Email settings
        email_frame = tk.Frame(main_frame, bg="#f0f0f0")
        email_frame.pack(fill=tk.X, pady=10)

        tk.Label(email_frame, text="Email Settings:", bg="#f0f0f0", 
                font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(10, 5))

        tk.Label(email_frame, text="Sender Email:", bg="#f0f0f0", 
                font=("Segoe UI", 10)).pack(anchor="w")
        self.sender_entry = tk.Entry(email_frame, width=50, font=("Segoe UI", 10))
        self.sender_entry.pack(fill=tk.X, pady=2)

        tk.Label(email_frame, text="Sender SMTP Password (App Password):", bg="#f0f0f0", 
                font=("Segoe UI", 10)).pack(anchor="w", pady=(10, 0))
        self.smtp_entry = tk.Entry(email_frame, width=50, show="*", font=("Segoe UI", 10))
        self.smtp_entry.pack(fill=tk.X, pady=2)

        tk.Label(email_frame, text="Receiver Email:", bg="#f0f0f0", 
                font=("Segoe UI", 10)).pack(anchor="w", pady=(10, 0))
        self.receiver_entry = tk.Entry(email_frame, width=50, font=("Segoe UI", 10))
        self.receiver_entry.pack(fill=tk.X, pady=2)

        # Progress bar with label
        progress_frame = tk.Frame(main_frame, bg="#f0f0f0")
        progress_frame.pack(fill=tk.X, pady=15)
        
        self.progress_label = tk.Label(progress_frame, text="Ready to encrypt...", bg="#f0f0f0", 
                                      font=("Segoe UI", 9), fg="#666666")
        self.progress_label.pack(anchor="w", pady=(0, 5))
        
        self.progress = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress.pack(fill=tk.X)

        # Encrypt button
        encrypt_btn = tk.Button(main_frame, text="Encrypt & Send Password", bg="#3a6ea5", fg="white",
                  font=("Segoe UI", 11, "bold"), height=2, width=25,
                  command=self.start_encryption)
        encrypt_btn.pack(pady=10)
        self._add_hover(encrypt_btn, normal_bg="#3a6ea5", hover_bg="#558cc9")

    def browse_encrypt_folder(self):
        folder_selected = filedialog.askdirectory(title="Select Folder to Encrypt")
        if folder_selected:
            self.folder_entry.delete(0, tk.END)
            self.folder_entry.insert(0, folder_selected)

    def start_encryption(self):
        folder_path = self.folder_entry.get()
        sender = self.sender_entry.get()
        smtp_pass = self.smtp_entry.get()
        receiver = self.receiver_entry.get()
        
        if not all([folder_path, sender, smtp_pass, receiver]):
            messagebox.showerror("Error", "Please fill all fields")
            return
            
        if not os.path.isdir(folder_path):
            messagebox.showerror("Error", "Invalid folder path")
            return
        
        # Disable button and start progress
        self.progress['value'] = 0
        self.progress_label.config(text="Starting encryption process...")
        self.encrypt_win.update()
            
        # Run encryption in a separate thread to avoid GUI freezing
        self.encrypt_win.after(100, lambda: self.encrypt_folder(folder_path, sender, smtp_pass, receiver))

    # ------------------- DECRYPT WINDOW ------------------- #
    def decrypt_window(self):
        self.decrypt_win = tk.Toplevel(self.root)
        self.decrypt_win.title("Decrypt Folder")
        self.decrypt_win.geometry("500x420")
        self.decrypt_win.configure(bg="#f0f0f0")
        self.decrypt_win.resizable(False, False)
        
        # Center the window
        self.decrypt_win.transient(self.root)
        self.decrypt_win.grab_set()
        
        main_frame = tk.Frame(self.decrypt_win, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title = tk.Label(main_frame, text="Folder Decryption", font=("Segoe UI", 16, "bold"), 
                        bg="#f0f0f0", fg="#2c3e50")
        title.pack(pady=(0, 15))

        # Folder selection for decryption
        folder_frame = tk.Frame(main_frame, bg="#f0f0f0")
        folder_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(folder_frame, text="Select Encrypted Folder:", bg="#f0f0f0", 
                font=("Segoe UI", 10)).pack(anchor="w")
        
        entry_frame = tk.Frame(folder_frame, bg="#f0f0f0")
        entry_frame.pack(fill=tk.X, pady=5)
        
        self.decrypt_folder_entry = tk.Entry(entry_frame, width=50, font=("Segoe UI", 10))
        self.decrypt_folder_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        browse_btn = tk.Button(entry_frame, text="Browse", command=self.browse_decrypt_folder, 
                              bg="#3a6ea5", fg="white", font=("Segoe UI", 9), width=10)
        browse_btn.pack(side=tk.RIGHT)
        self._add_hover(browse_btn, normal_bg="#3a6ea5", hover_bg="#558cc9")

        # Password entry
        tk.Label(main_frame, text="Decryption Password:", bg="#f0f0f0", 
                font=("Segoe UI", 10)).pack(anchor="w", pady=(15, 0))
        self.password_entry = tk.Entry(main_frame, width=50, show="*", font=("Segoe UI", 10))
        self.password_entry.pack(fill=tk.X, pady=5)

        # Show password checkbox
        self.show_password = tk.BooleanVar()
        show_pass_check = tk.Checkbutton(main_frame, text="Show password", variable=self.show_password,
                                        bg="#f0f0f0", font=("Segoe UI", 9),
                                        command=self.toggle_password_visibility)
        show_pass_check.pack(anchor="w", pady=5)

        # Progress bar with label
        progress_frame = tk.Frame(main_frame, bg="#f0f0f0")
        progress_frame.pack(fill=tk.X, pady=15)
        
        self.decrypt_progress_label = tk.Label(progress_frame, text="Ready to decrypt...", bg="#f0f0f0", 
                                              font=("Segoe UI", 9), fg="#666666")
        self.decrypt_progress_label.pack(anchor="w", pady=(0, 5))
        
        self.decrypt_progress = ttk.Progressbar(progress_frame, mode='determinate')
        self.decrypt_progress.pack(fill=tk.X)

        # DECRYPT BUTTON
        button_frame = tk.Frame(main_frame, bg="#f0f0f0")
        button_frame.pack(fill=tk.X, pady=10)
        
        decrypt_btn = tk.Button(button_frame, text="DECRYPT FOLDER", bg="#2a9d8f", fg="white",
                  font=("Segoe UI", 12, "bold"), height=2, width=25,
                  command=self.start_decryption)
        decrypt_btn.pack(pady=10)
        self._add_hover(decrypt_btn, normal_bg="#2a9d8f", hover_bg="#45b7a8")

    def toggle_password_visibility(self):
        if self.show_password.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def browse_decrypt_folder(self):
        folder_selected = filedialog.askdirectory(title="Select Encrypted Folder")
        if folder_selected:
            self.decrypt_folder_entry.delete(0, tk.END)
            self.decrypt_folder_entry.insert(0, folder_selected)

    def start_decryption(self):
        folder_path = self.decrypt_folder_entry.get()
        password = self.password_entry.get()
        
        if not all([folder_path, password]):
            messagebox.showerror("Error", "Please fill all fields")
            return
            
        if not os.path.isdir(folder_path):
            messagebox.showerror("Error", "Invalid folder path")
            return
        
        # Disable button and start progress
        self.decrypt_progress['value'] = 0
        self.decrypt_progress_label.config(text="Starting decryption process...")
        self.decrypt_win.update()
            
        # Run decryption in a separate thread to avoid GUI freezing
        self.decrypt_win.after(100, lambda: self.decrypt_folder(folder_path, password))

    # ------------------- ENCRYPTION/DECRYPTION LOGIC ------------------- #
    def encrypt_folder(self, folder_path, sender, smtp_pass, receiver):
        try:
            # Generate a secure password
            password = secrets.token_urlsafe(16)
            
            print(f"=== FOLDER ENCRYPTION STARTED ===")
            print(f"Original folder: {folder_path}")
            
            # Update progress
            self.progress['value'] = 10
            self.progress_label.config(text="Scanning files...")
            self.encrypt_win.update()
            
            # Count files first
            file_count = 0
            encrypted_files = 0
            for root, dirs, files in os.walk(folder_path):
                file_count += len(files)
            
            print(f"Found {file_count} files to encrypt")
            
            if file_count == 0:
                raise Exception("No files found in the selected folder")
            
            # Encrypt each file individually in the folder
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip already encrypted files
                    if file_path.endswith('.enc'):
                        continue
                    
                    # Update progress for each file
                    progress_percent = 10 + (encrypted_files / file_count) * 80
                    self.progress['value'] = progress_percent
                    self.progress_label.config(text=f"Encrypting file {encrypted_files + 1} of {file_count}...")
                    self.encrypt_win.update()
                    
                    # Encrypt the individual file
                    encrypted_file_path = file_path + ".enc"
                    self.aes_encrypt(file_path, encrypted_file_path, password)
                    
                    # Remove the original file after successful encryption
                    os.remove(file_path)
                    encrypted_files += 1
            
            # Update progress
            self.progress['value'] = 90
            self.progress_label.config(text="Sending email with password...")
            self.encrypt_win.update()
            
            # Send email with password
            try:
                self.send_email(sender, smtp_pass, receiver, password, folder_path)
                print("Email sent successfully")
            except Exception as email_error:
                print(f"Email failed: {email_error}")
                # Don't raise error here, just notify user
                messagebox.showwarning("Email Warning", f"Encryption completed but email failed: {email_error}")
            
            # Complete progress
            self.progress['value'] = 100
            self.progress_label.config(text="Encryption completed successfully!")
            self.encrypt_win.update()
            time.sleep(1)  # Show completion for 1 second
            
            # Show success message
            self.encrypt_win.destroy()
            
            success_message = f"""✅ FOLDER ENCRYPTION SUCCESSFUL!

📁 Folder: {os.path.basename(folder_path)}
📊 Files Encrypted: {file_count}
📧 Password sent to: {receiver}

📍 Encrypted folder location:
{folder_path}

⚠️ IMPORTANT:
• All files in the folder are now encrypted (.enc extension)
• Original files have been removed
• Password has been sent to your email
• Save the password securely for decryption"""

            messagebox.showinfo("Encryption Complete", success_message)
                               
        except Exception as e:
            self.progress['value'] = 0
            self.progress_label.config(text="Encryption failed!")
            print(f"❌ ENCRYPTION ERROR: {str(e)}")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_folder(self, folder_path, password):
        try:
            print(f"\n=== FOLDER DECRYPTION STARTED ===")
            print(f"Encrypted folder: {folder_path}")
            
            # Update progress
            self.decrypt_progress['value'] = 10
            self.decrypt_progress_label.config(text="Scanning encrypted files...")
            self.decrypt_win.update()
            
            # Count encrypted files first
            encrypted_files = []
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file.endswith('.enc'):
                        encrypted_files.append(os.path.join(root, file))
            
            file_count = len(encrypted_files)
            print(f"Found {file_count} encrypted files to decrypt")
            
            if file_count == 0:
                raise Exception("No encrypted files (.enc) found in the selected folder")
            
            # Decrypt each file individually in the folder
            decrypted_files = 0
            for encrypted_file_path in encrypted_files:
                # Update progress for each file
                progress_percent = 10 + (decrypted_files / file_count) * 80
                self.decrypt_progress['value'] = progress_percent
                self.decrypt_progress_label.config(text=f"Decrypting file {decrypted_files + 1} of {file_count}...")
                self.decrypt_win.update()
                
                # Get the original file path (remove .enc extension)
                original_file_path = encrypted_file_path[:-4]  # Remove .enc extension
                
                # Decrypt the file
                self.aes_decrypt(encrypted_file_path, original_file_path, password)
                
                # Remove the encrypted file after successful decryption
                os.remove(encrypted_file_path)
                decrypted_files += 1
            
            # Update progress
            self.decrypt_progress['value'] = 100
            self.decrypt_progress_label.config(text="Decryption completed successfully!")
            self.decrypt_win.update()
            time.sleep(1)  # Show completion for 1 second
            
            # Show success message
            self.decrypt_win.destroy()
            
            success_msg = f"""✅ FOLDER DECRYPTION SUCCESSFUL!

📁 Folder: {os.path.basename(folder_path)}
📊 Files Decrypted: {file_count}

📍 Location: {folder_path}

🎉 Your folder has been successfully decrypted!
• All encrypted files have been restored to original format
• Encrypted files (.enc) have been removed
• Original files are now accessible"""

            messagebox.showinfo("Decryption Complete", success_msg)
            print("=== FOLDER DECRYPTION COMPLETED ===\n")
                               
        except Exception as e:
            self.decrypt_progress['value'] = 0
            self.decrypt_progress_label.config(text="Decryption failed!")
            print(f"❌ DECRYPTION ERROR: {str(e)}")
            error_msg = f"Decryption failed: {str(e)}"
            
            if "Invalid password" in str(e) or "corrupted" in str(e).lower():
                error_msg = """❌ DECRYPTION FAILED!

Possible reasons:
• Incorrect password
• Files are corrupted  
• Folder was not encrypted with this tool

💡 Tips:
• Check the password carefully
• Make sure you're selecting the correct encrypted folder
• Verify the folder was encrypted with this tool"""
            
            messagebox.showerror("Decryption Failed", error_msg)

    def aes_encrypt(self, input_file, output_file, password):
        print(f"Encrypting {input_file} -> {output_file}")
        
        # Generate a random salt
        salt = get_random_bytes(16)
        
        # Derive key from password using PBKDF2
        key = PBKDF2(password, salt, 32, count=1000000)
        
        # Generate a random initialization vector
        iv = get_random_bytes(16)
        
        # Create AES cipher in GCM mode
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        
        # Read and encrypt the file data
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Create the encrypted file
        with open(output_file, 'wb') as f:
            f.write(salt)
            f.write(iv)
            f.write(tag)
            f.write(ciphertext)
        
        print(f"Encryption completed: {len(ciphertext)} bytes encrypted")

    def aes_decrypt(self, input_file, output_file, password):
        print(f"Decrypting {input_file} -> {output_file}")
        
        with open(input_file, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()
        
        print(f"Read from file: salt={len(salt)}, iv={len(iv)}, tag={len(tag)}, ciphertext={len(ciphertext)}")
        
        # Derive key from password using PBKDF2
        key = PBKDF2(password, salt, 32, count=1000000)
        
        # Create AES cipher in GCM mode
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        
        # Decrypt and verify the data
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            print(f"Decryption verification failed: {e}")
            raise Exception("Invalid password or corrupted file")
        
        # Write the decrypted data to output file
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        print(f"Decryption completed: {len(plaintext)} bytes decrypted")

    def send_email(self, sender, smtp_pass, receiver, password, folder_path):
        # Email content
        subject = "Your Folder Encryption Password"
        body = f"""
        Your folder has been encrypted successfully.
        
        Folder: {os.path.basename(folder_path)}
        Location: {folder_path}
        Encryption Password: {password}
        
        Please keep this password secure and do not share it with anyone.
        
        To decrypt the folder, use the provided password in the decryption tool.
        
        IMPORTANT: All files in the folder have been encrypted and now have .enc extension.
        Original files have been removed for security.
        """
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = receiver
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email using Gmail SMTP
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender, smtp_pass)
            server.sendmail(sender, receiver, msg.as_string())
            server.quit()
        except Exception as e:
            raise Exception(f"Failed to send email: {str(e)}")

# ------------------- RUN APP ------------------- #
if __name__ == "__main__":
    root = tk.Tk()
    app = FolderEncryptorGUI(root)
    root.mainloop()