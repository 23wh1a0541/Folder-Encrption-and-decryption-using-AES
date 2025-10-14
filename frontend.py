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
import logging
import json
import hashlib
import re
from datetime import datetime
import requests
from io import BytesIO
import sqlite3
import uuid
import sys


# ==================== EMAIL CONFIGURATION ====================
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'tasleemanasreenshaik09@gmail.com',  # Change this to your email
    'sender_password': 'cjrw frib xssk lwsd'   # Change this to your app password
}

# ==================== PATH MANAGEMENT ====================
def get_base_path():
    """Get the correct base path whether running as script or executable"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)   
    else:
        return os.path.dirname(os.path.abspath(__file__))

BASE_PATH = get_base_path()

# ==================== DATABASE MANAGER ====================
class DatabaseManager:
    def __init__(self):
        self.db_path = os.path.join(BASE_PATH, "users.db")
        self.init_database()
    
    def init_database(self):
        """Initialize the database and create users table"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT UNIQUE NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    security_question TEXT NOT NULL,
                    security_answer_hash TEXT NOT NULL,
                    registration_date TEXT NOT NULL,
                    last_login TEXT,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    attempt_time TEXT NOT NULL,
                    success INTEGER DEFAULT 0,
                    ip_address TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    expires_at REAL NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    used INTEGER DEFAULT 0
                )
            ''')
            
            conn.commit()
            conn.close()
            print("✅ Database initialized successfully")
            
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
    
    def register_user(self, username, email, password, security_question, security_answer):
        """Register a new user"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if username or email already exists
            cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                conn.close()
                return False, "Username or email already exists"
            
            # Generate unique user ID
            user_id = str(uuid.uuid4())[:8]
            
            # Hash password and security answer
            password_hash = self._hash_password(password)
            security_answer_hash = self._hash_password(security_answer.lower())
            
            # Insert new user
            cursor.execute('''
                INSERT INTO users (user_id, username, email, password_hash, security_question, security_answer_hash, registration_date)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, username, email, password_hash, security_question, security_answer_hash, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            return True, "Registration successful! You can now login."
            
        except Exception as e:
            return False, f"Registration failed: {str(e)}"
    
    def verify_user(self, username, password):
        """Verify user login credentials"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
            user = cursor.fetchone()
            
            if not user:
                conn.close()
                return False, "User not found or inactive"
            
            # Verify password
            stored_hash = user[4]  # password_hash column
            if self._verify_password(password, stored_hash):
                # Update last login
                cursor.execute("UPDATE users SET last_login = ? WHERE username = ?", 
                             (datetime.now().isoformat(), username))
                conn.commit()
                conn.close()
                return True, "Login successful"
            else:
                conn.close()
                return False, "Invalid password"
                
        except Exception as e:
            return False, f"Login failed: {str(e)}"
    
    def verify_security_answer(self, username, security_answer):
        """Verify security answer for password reset"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT security_answer_hash FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            
            if not result:
                conn.close()
                return False, "User not found"
            
            stored_hash = result[0]
            if self._verify_password(security_answer.lower(), stored_hash):
                conn.close()
                return True, "Security answer verified"
            else:
                conn.close()
                return False, "Incorrect security answer"
                
        except Exception as e:
            return False, f"Verification failed: {str(e)}"
    
    def update_password(self, username, new_password):
        """Update user password"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            new_password_hash = self._hash_password(new_password)
            cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", 
                         (new_password_hash, username))
            
            conn.commit()
            conn.close()
            return True, "Password updated successfully"
            
        except Exception as e:
            return False, f"Password update failed: {str(e)}"
    
    def get_security_question(self, username):
        """Get security question for a user"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT security_question FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            
            conn.close()
            return result[0] if result else None
            
        except Exception as e:
            print(f"Error getting security question: {e}")
            return None

    def get_user_by_email(self, email):
        """Get user by email address"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT username, email FROM users WHERE email = ?", (email,))
            result = cursor.fetchone()
            
            conn.close()
            return result  # Returns (username, email) if found, None otherwise
            
        except Exception as e:
            print(f"Error getting user by email: {e}")
            return None

    def update_password_by_email(self, email, new_password):
        """Update user password by email"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            new_password_hash = self._hash_password(new_password)
            cursor.execute("UPDATE users SET password_hash = ? WHERE email = ?", 
                         (new_password_hash, email))
            
            conn.commit()
            conn.close()
            return True, "Password updated successfully"
            
        except Exception as e:
            return False, f"Password update failed: {str(e)}"

    def _hash_password(self, password):
        """Hash password using SHA-256 with salt"""
        salt = "supraja_tech_2025"
        return hashlib.sha256((password + salt).encode()).hexdigest()

    def _verify_password(self, password, stored_hash):
        """Verify password against stored hash"""
        return self._hash_password(password) == stored_hash

    def create_password_reset_token(self, email):
        """Create a password reset token for the user"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Generate a unique reset token
            reset_token = str(uuid.uuid4())
            expires_at = datetime.now().timestamp() + 3600  # 1 hour from now
            
            # Insert the reset token
            cursor.execute('''
                INSERT INTO password_reset_tokens (email, token, expires_at)
                VALUES (?, ?, ?)
            ''', (email, reset_token, expires_at))
            
            conn.commit()
            conn.close()
            return reset_token
            
        except Exception as e:
            print(f"Error creating reset token: {e}")
            return None

    def verify_reset_token(self, token):
        """Verify if a reset token is valid and not expired"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT email, expires_at, used FROM password_reset_tokens 
                WHERE token = ? AND used = 0 AND expires_at > ?
            ''', (token, datetime.now().timestamp()))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return True, result[0]  # Token is valid, return email
            else:
                return False, "Invalid or expired token"
                
        except Exception as e:
            return False, f"Error verifying token: {e}"

    def mark_token_used(self, token):
        """Mark a reset token as used"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE password_reset_tokens SET used = 1 WHERE token = ?
            ''', (token,))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error marking token as used: {e}")
            return False
        
    def _assess_password_strength(self, password):
        """Assess password strength (similar to PasswordManager method)"""
        if not password:
            return 0, "No password provided"
        
        common_passwords = {"password", "123456", "12345678", "1234", "qwerty"}
        if password.lower() in common_passwords:
            return 0, "Password is too common"
        
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("At least 8 characters")
        
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Uppercase letters")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Lowercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Numbers")
        
        if any(not c.isalnum() for c in password):
            score += 1
        else:
            feedback.append("Special characters")
        
        if score >= 5:
            return score, "Strong password"
        elif score >= 3:
            return score, "Medium strength"
        else:
            return score, f"Weak: Add {', '.join(feedback[:2])}"

# ==================== AUTHENTICATION MANAGER ====================
class AuthManager:
    def __init__(self):
        self.db = DatabaseManager()
        self.current_user = None
        self.login_callback = None
    
    def set_login_callback(self, callback):
        """Set callback function to be called after successful login"""
        self.login_callback = callback
    
    def register(self, username, email, password, confirm_password, security_question, security_answer):
        """Handle user registration"""
        # Validation
        if not all([username, email, password, confirm_password, security_question, security_answer]):
            return False, "All fields are required"
        
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return False, "Invalid email format"
        
        if password != confirm_password:
            return False, "Passwords do not match"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters"
        
        # Register user
        return self.db.register_user(username, email, password, security_question, security_answer)
    
    def login(self, username, password):
        """Handle user login"""
        if not username or not password:
            return False, "Username and password are required"
        
        return self.db.verify_user(username, password)
    
    def reset_password(self, username, security_answer, new_password, confirm_password):
        """Handle password reset"""
        if not all([username, security_answer, new_password, confirm_password]):
            return False, "All fields are required"
        
        if new_password != confirm_password:
            return False, "Passwords do not match"
        
        if len(new_password) < 6:
            return False, "Password must be at least 6 characters"
        
        # Verify security answer
        success, message = self.db.verify_security_answer(username, security_answer)
        if not success:
            return False, message
        
        # Update password
        return self.db.update_password(username, new_password)
    
    def get_security_question(self, username):
        """Get security question for password reset"""
        return self.db.get_security_question(username)

    def set_current_user(self, username):
        """Set current logged in user"""
        self.current_user = username
    
    def get_current_user(self):
        """Get current logged in user"""
        return self.current_user
    
    def logout(self):
        """Logout current user"""
        self.current_user = None
    
    def initiate_password_reset(self, email):
        """Initiate password reset process with real email sending"""
        user_data = self.db.get_user_by_email(email)
        if not user_data:
            return False, "No account found with this email address"
        
        username, user_email = user_data
        
        # Generate reset token
        reset_token = self.db.create_password_reset_token(email)
        if not reset_token:
            return False, "Failed to create reset token"
        
        # Send reset email
        success, message = self._send_password_reset_email(email, reset_token)
        if success:
            return True, f"Password reset instructions sent to {email}"
        else:
            return False, message

    def _send_password_reset_email(self, email, reset_token):
        """Send actual password reset email"""
        try:
            # Check if email credentials are configured
            if (EMAIL_CONFIG['sender_email'] == 'your-email@gmail.com' or 
                EMAIL_CONFIG['sender_password'] == 'your-app-password'):
                return False, "Email credentials not configured. Please update EMAIL_CONFIG with your Gmail credentials."
            
            # Create reset instructions
            reset_instructions = f"""
Password Reset Request - Secure Folder Encryption

Hello,

You have requested to reset your password for the Secure Folder Encryption application.

Please use the following reset token to reset your password:

Reset Token: {reset_token}

To reset your password:

1. Open the Secure Folder Encryption application
2. Click on "Forgot Password?" 
3. Enter this reset token when prompted
4. Create your new password

This token will expire in 1 hour.

If you did not request this reset, please ignore this email.

Best regards,
Secure Folder Encryption Team
Supraja Technologies
"""
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = EMAIL_CONFIG['sender_email']
            msg['To'] = email
            msg['Subject'] = "Password Reset Request - Secure Folder Encryption"
            msg.attach(MIMEText(reset_instructions, 'plain'))
            
            # Send email
            server = smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
            server.starttls()
            server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
            server.sendmail(EMAIL_CONFIG['sender_email'], email, msg.as_string())
            server.quit()
            
            print(f"✅ Password reset email sent to {email}")
            print(f"📧 Reset token: {reset_token}")
            
            return True, "Email sent successfully"
            
        except smtplib.SMTPAuthenticationError:
            error_msg = "Email authentication failed. Please check your Gmail credentials and App Password."
            print(f"❌ {error_msg}")
            return False, error_msg
        except Exception as e:
            error_msg = f"Failed to send email: {str(e)}"
            print(f"❌ {error_msg}")
            return False, error_msg

    def reset_password_with_token(self, token, new_password):
        """Reset password using a valid token"""
        # Verify token
        is_valid, result = self.db.verify_reset_token(token)
        if not is_valid:
            return False, result
        
        email = result
        
        # Update password
        success, message = self.db.update_password_by_email(email, new_password)
        if success:
            # Mark token as used
            self.db.mark_token_used(token)
            return True, "Password reset successfully"
        else:
            return False, message

    def verify_token_and_reset(self, token, new_password, confirm_password):
        """Verify token and reset password"""
        if not token:
            return False, "Reset token is required"
        
        if new_password != confirm_password:
            return False, "Passwords do not match"
        
        if len(new_password) < 6:
            return False, "Password must be at least 6 characters"
        
        return self.reset_password_with_token(token, new_password)

# ==================== ASSET MANAGER ====================
class AssetManager:
    def __init__(self):
        self.assets_dir = self._setup_assets_directory()
        self.current_background_path = None
    
    def _setup_assets_directory(self):
        """Create and return assets directory path"""
        assets_dir = os.path.join(BASE_PATH, "assets")
        os.makedirs(assets_dir, exist_ok=True)
        return assets_dir
    
    def get_background_path(self):
        """Get background image path - PRIORITIZE USER'S IMAGE"""
        # First, check for custom background in assets folder
        custom_bg_path = os.path.join(self.assets_dir, "custom_background.png")
        if os.path.exists(custom_bg_path):
            print(f"✅ Found custom background: {custom_bg_path}")
            self.current_background_path = custom_bg_path
            return custom_bg_path
        
        # Check for other common image files in assets folder
        possible_names = [
            "background", "bg", "background_image", "back", 
            "siri1", "background1", "main_bg"
        ]
        
        possible_extensions = [".png", ".jpg", ".jpeg", ".gif", ".bmp"]
        
        # Check all combinations in assets folder
        for name in possible_names:
            for ext in possible_extensions:
                potential_path = os.path.join(self.assets_dir, f"{name}{ext}")
                if os.path.exists(potential_path):
                    print(f"✅ Found background: {potential_path}")
                    self.current_background_path = potential_path
                    return potential_path
        
        # Check in base directory
        for name in possible_names:
            for ext in possible_extensions:
                potential_path = os.path.join(BASE_PATH, f"{name}{ext}")
                if os.path.exists(potential_path):
                    print(f"✅ Found background: {potential_path}")
                    self.current_background_path = potential_path
                    return potential_path
        
        # If no image found, create default
        print("⚠️ No background image found. Creating default...")
        self.current_background_path = self._create_default_background()
        return self.current_background_path
    
    def _create_default_background(self):
        """Create a default gradient background"""
        img = Image.new('RGB', (1920, 1080), color='#1e1e1e')
        draw = ImageDraw.Draw(img)
        
        # Draw a simple gradient
        for i in range(1080):
            r = int(30 + (i / 1080) * 50)
            g = int(46 + (i / 1080) * 50)
            b = int(105 + (i / 1080) * 50)
            draw.line([(0, i), (1920, i)], fill=(r, g, b))
        
        # Save to assets folder
        default_bg_path = os.path.join(self.assets_dir, "default_background.png")
        img.save(default_bg_path)
        return default_bg_path
    
    def set_custom_background(self, image_path):
        """Set a custom background image"""
        try:
            # Copy to assets folder as custom_background.png
            destination = os.path.join(self.assets_dir, "custom_background.png")
            
            # Convert and save as PNG for consistency
            img = Image.open(image_path).convert("RGBA")
            
            # Resize to optimal size for background
            screen_width, screen_height = 1920, 1080  # Default large size
            img = img.resize((screen_width, screen_height), Image.LANCZOS)
            
            img.save(destination)
            self.current_background_path = destination
            print(f"✅ Custom background saved to: {destination}")
            return True
        except Exception as e:
            print(f"❌ Failed to set custom background: {e}")
            return False

    def download_supraja_logo(self):
        """Download Supraja Technologies logo from the internet"""
        try:
            # Multiple possible logo URLs for Supraja Technologies
            logo_urls = [
                "https://via.placeholder.com/120x120/3a6ea5/ffffff?text=ST",
                "https://via.placeholder.com/120x120/2a9d8f/ffffff?text=ST",
                "https://via.placeholder.com/120x120/1e1e1e/ffffff?text=ST"
            ]
            
            logo_path = os.path.join(self.assets_dir, "supraja_logo.png")
            
            for url in logo_urls:
                try:
                    print(f"🔄 Trying to download logo from: {url}")
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        # Save the logo
                        with open(logo_path, 'wb') as f:
                            f.write(response.content)
                        print(f"✅ Logo downloaded successfully: {logo_path}")
                        return logo_path
                except Exception as e:
                    print(f"❌ Failed to download from {url}: {e}")
                    continue
            
            # Create a simple logo if download fails
            print("⚠️ Creating default logo...")
            return self._create_default_logo()
            
        except Exception as e:
            print(f"❌ Logo download failed: {e}")
            return self._create_default_logo()

    def _create_default_logo(self):
        """Create a default Supraja Technologies logo"""
        try:
            logo_path = os.path.join(self.assets_dir, "supraja_logo.png")
            
            # Create a professional-looking logo
            img = Image.new('RGBA', (120, 120), color=(0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            
            # Draw circular background
            draw.ellipse([0, 0, 120, 120], fill='#3a6ea5')
            
            # Draw 'ST' text using rectangles (simplified)
            draw.rectangle([30, 40, 50, 80], fill='white')  # S part 1
            draw.rectangle([60, 40, 80, 80], fill='white')  # T part 1
            
            img.save(logo_path)
            print(f"✅ Default logo created: {logo_path}")
            return logo_path
        except Exception as e:
            print(f"❌ Failed to create default logo: {e}")
            return None

# ==================== LOGGING SYSTEM ====================
class EncryptionLogger:
    def __init__(self, app_name="FolderEncryptor"):
        self.app_name = app_name
        self.setup_logging()
        
    def setup_logging(self):
        """Setup comprehensive logging configuration"""
        log_dir = os.path.join(BASE_PATH, "logs")
        os.makedirs(log_dir, exist_ok=True)
        
        log_filename = os.path.join(log_dir, f"{self.app_name}_{datetime.now().strftime('%Y%m%d')}.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(self.app_name)
        self.logger.info(f"=== {self.app_name} Started ===")
    
    def log_encryption_start(self, folder_path, file_count):
        folder_hash = self._hash_folder_name(folder_path)
        self.logger.info(f"ENCRYPTION_START | Folder: {folder_hash} | Files: {file_count}")
    
    def log_encryption_complete(self, folder_path, success_count, total_files):
        folder_hash = self._hash_folder_name(folder_path)
        self.logger.info(f"ENCRYPTION_COMPLETE | Folder: {folder_hash} | Success: {success_count}/{total_files}")
    
    def log_decryption_attempt(self, folder_path, success):
        folder_hash = self._hash_folder_name(folder_path)
        status = "SUCCESS" if success else "FAILED"
        self.logger.info(f"DECRYPTION_ATTEMPT | Folder: {folder_hash} | Status: {status}")
    
    def log_error(self, operation, error_message, folder_path=""):
        folder_hash = self._hash_folder_name(folder_path) if folder_path else "N/A"
        self.logger.error(f"ERROR | Operation: {operation} | Folder: {folder_hash} | Error: {error_message}")
    
    def _hash_folder_name(self, folder_path):
        folder_name = os.path.basename(folder_path)
        return hashlib.md5(folder_name.encode()).hexdigest()[:8]

# ==================== INPUT VALIDATOR ====================
class InputValidator:
    @staticmethod
    def validate_folder_path(path):
        if not path or not path.strip():
            return False, "Folder path cannot be empty"
        if not os.path.exists(path):
            return False, "Folder path does not exist"
        if not os.path.isdir(path):
            return False, "Path is not a directory"
        try:
            test_file = os.path.join(path, f".test_{int(time.time())}")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
        except PermissionError:
            return False, "No write permission for this folder"
        except Exception:
            return False, "Cannot access folder"
        return True, "Valid folder"

    @staticmethod
    def validate_email_address(email):
        if not email or not email.strip():
            return False, "Email cannot be empty"
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(pattern, email):
            return True, "Valid email"
        else:
            return False, "Invalid email format"

    @staticmethod
    def validate_password_strength(password, min_length=8):
        if len(password) < min_length:
            return False, f"Password must be at least {min_length} characters"
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        score = sum([has_upper, has_lower, has_digit, has_special])
        if score >= 3:
            return True, "Strong password"
        elif score >= 2:
            return True, "Medium strength password"
        else:
            return False, "Weak password - include uppercase, lowercase, numbers, and special characters"

# ==================== PASSWORD MANAGER ====================
class PasswordManager:
    def __init__(self):
        self.common_passwords = self._load_common_passwords()
    
    def _load_common_passwords(self):
        common = [
            "password", "123456", "12345678", "1234", "qwerty", "12345",
            "dragon", "baseball", "football", "letmein", "monkey", "abc123"
        ]
        return set(common)
    
    def assess_password_strength(self, password):
        if not password:
            return 0, "No password provided"
        if password.lower() in self.common_passwords:
            return 0, "Password is too common"
        
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("At least 8 characters")
        
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Uppercase letters")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Lowercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Numbers")
        
        if any(not c.isalnum() for c in password):
            score += 1
        else:
            feedback.append("Special characters")
        
        if len(set(password)) >= 8:
            score += 1
        else:
            feedback.append("More unique characters")
        
        if score >= 5:
            return score, "Strong password"
        elif score >= 3:
            return score, "Medium strength"
        else:
            return score, f"Weak: Add {', '.join(feedback[:2])}"
    
    def generate_strong_password(self, length=16):
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        while True:
            password = ''.join(secrets.choice(alphabet) for _ in range(length))
            score, _ = self.assess_password_strength(password)
            if score >= 5:
                return password

# ==================== THEME MANAGER ====================
class ThemeManager:
    def __init__(self):
        self.current_theme = "dark"
        self.themes = {
            "dark": {
                "bg": "#1e1e1e",
                "fg": "#ffffff",
                "accent": "#3a6ea5",
                "secondary": "#2a9d8f",
                "panel_bg": "#2d2d2d",
                "text_muted": "#cccccc",
                "border": "#3a6ea5",
                "button_bg": "#3a6ea5",
                "button_fg": "white"
            },
            "light": {
                "bg": "#f5f5f5",
                "fg": "#333333",
                "accent": "#3a6ea5",
                "secondary": "#2a9d8f",
                "panel_bg": "#ffffff",
                "text_muted": "#666666",
                "border": "#3a6ea5",
                "button_bg": "#3a6ea5",
                "button_fg": "white"
            }
        }
    
    def get_theme(self):
        return self.themes[self.current_theme]
    
    def toggle_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        return self.get_theme()

# ==================== AUTHENTICATION GUI ====================
class AuthGUI:
    def __init__(self, root, auth_manager):
        self.root = root
        self.auth_manager = auth_manager
        self.current_frame = None
        
        # Setup window
        self.root.title("Secure Folder Encryption - Authentication")
        self.root.geometry("1000x800")
        self.root.configure(bg='#1e1e1e')
        self.root.resizable(False, False)
        
        self._setup_styles()
        self.show_login_frame()
        self.center_window()

    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def _setup_styles(self):
        self.styles = {
            "bg": "#1e1e1e",
            "fg": "#ffffff",
            "accent": "#3a6ea5",
            "secondary": "#2a9d8f",
            "panel_bg": "#2d2d2d",
            "text_muted": "#cccccc",
            "error": "#e74c3c",
            "success": "#2ecc71"
        }

    def clear_frame(self):
        if self.current_frame:
            self.current_frame.destroy()

    # ---------------- LOGIN ----------------
    def show_login_frame(self):
        self.clear_frame()
        self.current_frame = tk.Frame(self.root, bg=self.styles["bg"], padx=40, pady=40)
        self.current_frame.pack(fill=tk.BOTH, expand=True)

        # Logo/Title
        title_frame = tk.Frame(self.current_frame, bg=self.styles["bg"])
        title_frame.pack(pady=(0, 30))
        
        tk.Label(title_frame, text="🔒", font=("Arial", 48), 
                bg=self.styles["bg"], fg=self.styles["accent"]).pack()
        
        tk.Label(title_frame, text="Secure Folder Encryption", 
                font=("Segoe UI", 24, "bold"), bg=self.styles["bg"], fg=self.styles["fg"]).pack(pady=(10, 5))
        
        tk.Label(title_frame, text="Please login to continue", 
                font=("Segoe UI", 12), bg=self.styles["bg"], fg=self.styles["text_muted"]).pack()

        # Login Form
        form_frame = tk.Frame(self.current_frame, bg=self.styles["panel_bg"], padx=30, pady=30)
        form_frame.pack(fill=tk.BOTH, expand=True)

        # Username
        tk.Label(form_frame, text="Username", font=("Segoe UI", 11, "bold"),
                bg=self.styles["panel_bg"], fg=self.styles["fg"]).pack(anchor="w", pady=(0, 5))
        
        self.login_username = tk.Entry(form_frame, font=("Segoe UI", 12), width=30, bg="#3d3d3d", fg="white",
                                    insertbackground="white", relief="flat")
        self.login_username.pack(fill=tk.X, pady=(0, 15))
        self.login_username.bind('<Return>', lambda e: self.login())

        # Password
        tk.Label(form_frame, text="Password", font=("Segoe UI", 11, "bold"),
                bg=self.styles["panel_bg"], fg=self.styles["fg"]).pack(anchor="w", pady=(0, 5))
        
        self.login_password = tk.Entry(form_frame, font=("Segoe UI", 12), width=30, show="•", 
                                    bg="#3d3d3d", fg="white", insertbackground="white", relief="flat")
        self.login_password.pack(fill=tk.X, pady=(0, 20))
        self.login_password.bind('<Return>', lambda e: self.login())

        # Login Button
        login_btn = tk.Button(form_frame, text="Login", font=("Segoe UI", 12, "bold"),
                            bg=self.styles["accent"], fg="white", relief="flat", cursor="hand2",
                            command=self.login, width=20, height=2)
        login_btn.pack(pady=(10, 15))
        self._add_hover_effect(login_btn, self.styles["accent"], "#558cc9")

        # Links
        links_frame = tk.Frame(form_frame, bg=self.styles["panel_bg"])
        links_frame.pack()
        
        tk.Button(links_frame, text="Register", font=("Segoe UI", 10), bg=self.styles["panel_bg"],
                fg=self.styles["accent"], relief="flat", cursor="hand2",
                command=self.show_register_frame).pack(side=tk.LEFT, padx=(0, 20))
        
        tk.Button(links_frame, text="Forgot Password?", font=("Segoe UI", 10), bg=self.styles["panel_bg"],
                fg=self.styles["accent"], relief="flat", cursor="hand2",
                command=self.show_forgot_password_frame).pack(side=tk.LEFT)

    def login(self):
        """Handle user login"""
        username = self.login_username.get().strip()
        password = self.login_password.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return

        success, message = self.auth_manager.login(username, password)
        if success:
            self.auth_manager.set_current_user(username)
            messagebox.showinfo("Success", f"Welcome {username}!")
            print(f"✅ User {username} logged in successfully")
            
            # Close auth window and trigger callback
            self.root.destroy()
            if self.auth_manager.login_callback:
                print("🚀 Launching main application...")
                self.auth_manager.login_callback()
            else:
                print("❌ No login callback set!")
        else:
            messagebox.showerror("Login Failed", message)

    # ---------------- REGISTER ----------------
    def show_register_frame(self):
        self.clear_frame()
        self.current_frame = tk.Frame(self.root, bg=self.styles["bg"], padx=40, pady=30)
        self.current_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_frame = tk.Frame(self.current_frame, bg=self.styles["bg"])
        title_frame.pack(pady=(0, 30))
        
        tk.Label(title_frame, text="👤", font=("Arial", 48), 
                bg=self.styles["bg"], fg=self.styles["accent"]).pack()
        
        tk.Label(title_frame, text="Create Account", 
                font=("Segoe UI", 28, "bold"), bg=self.styles["bg"], fg=self.styles["fg"]).pack(pady=(10, 5))

        # Main container for centering
        main_container = tk.Frame(self.current_frame, bg=self.styles["bg"])
        main_container.pack(expand=True, fill=tk.BOTH)

        # Center frame
        center_frame = tk.Frame(main_container, bg=self.styles["bg"])
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Registration Form
        form_frame = tk.Frame(center_frame, bg=self.styles["panel_bg"], padx=40, pady=35,
                            highlightthickness=2, highlightbackground=self.styles["accent"])
        form_frame.pack(padx=20, pady=20)

        # Configure grid for better alignment
        form_frame.columnconfigure(0, weight=1)
        form_frame.columnconfigure(1, weight=1)

        # Username
        tk.Label(form_frame, text="Username *", font=("Segoe UI", 12, "bold"),
                bg=self.styles["panel_bg"], fg=self.styles["fg"]).grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.reg_username = tk.Entry(form_frame, font=("Segoe UI", 12), width=25, bg="#3d3d3d", fg="white",
                                insertbackground="white", relief="flat")
        self.reg_username.grid(row=0, column=1, sticky="ew", pady=(0, 15), padx=(15, 0))

        # Email
        tk.Label(form_frame, text="Email *", font=("Segoe UI", 12, "bold"),
                bg=self.styles["panel_bg"], fg=self.styles["fg"]).grid(row=1, column=0, sticky="w", pady=(0, 8))
        self.reg_email = tk.Entry(form_frame, font=("Segoe UI", 12), width=25, bg="#3d3d3d", fg="white",
                                insertbackground="white", relief="flat")
        self.reg_email.grid(row=1, column=1, sticky="ew", pady=(0, 15), padx=(15, 0))

        # Password
        tk.Label(form_frame, text="Password *", font=("Segoe UI", 12, "bold"),
                bg=self.styles["panel_bg"], fg=self.styles["fg"]).grid(row=2, column=0, sticky="w", pady=(0, 8))
        self.reg_password = tk.Entry(form_frame, font=("Segoe UI", 12), width=25, show="•", 
                                bg="#3d3d3d", fg="white", insertbackground="white", relief="flat")
        self.reg_password.grid(row=2, column=1, sticky="ew", pady=(0, 15), padx=(15, 0))

        # Confirm Password
        tk.Label(form_frame, text="Confirm Password *", font=("Segoe UI", 12, "bold"),
                bg=self.styles["panel_bg"], fg=self.styles["fg"]).grid(row=3, column=0, sticky="w", pady=(0, 8))
        self.reg_confirm_password = tk.Entry(form_frame, font=("Segoe UI", 12), width=25, show="•", 
                                        bg="#3d3d3d", fg="white", insertbackground="white", relief="flat")
        self.reg_confirm_password.grid(row=3, column=1, sticky="ew", pady=(0, 15), padx=(15, 0))

        # Security Question
        tk.Label(form_frame, text="Security Question *", font=("Segoe UI", 12, "bold"),
                bg=self.styles["panel_bg"], fg=self.styles["fg"]).grid(row=4, column=0, sticky="w", pady=(0, 8))
        self.security_question = ttk.Combobox(form_frame, font=("Segoe UI", 12), width=23, state="readonly")
        self.security_question['values'] = [
            "What was your first pet's name?",
            "What city were you born in?",
            "What is your mother's maiden name?",
            "What was your first school name?",
            "What is your favorite book?",
            "What was your childhood nickname?"
        ]
        self.security_question.current(0)
        self.security_question.grid(row=4, column=1, sticky="ew", pady=(0, 15), padx=(15, 0))

        # Security Answer
        tk.Label(form_frame, text="Security Answer *", font=("Segoe UI", 12, "bold"),
                bg=self.styles["panel_bg"], fg=self.styles["fg"]).grid(row=5, column=0, sticky="w", pady=(0, 8))
        self.security_answer = tk.Entry(form_frame, font=("Segoe UI", 12), width=25, 
                                    bg="#3d3d3d", fg="white", insertbackground="white", relief="flat")
        self.security_answer.grid(row=5, column=1, sticky="ew", pady=(0, 25), padx=(15, 0))

        # Button Frame
        button_frame = tk.Frame(form_frame, bg=self.styles["panel_bg"])
        button_frame.grid(row=6, column=0, columnspan=2, pady=(10, 15), sticky="ew")

        # Create Account Button - LARGER and centered
        register_btn = tk.Button(button_frame, text="CREATE ACCOUNT", font=("Segoe UI", 14, "bold"),
                            bg=self.styles["accent"], fg="white", relief="flat", cursor="hand2",
                            command=self.register, width=20, height=2)
        register_btn.pack(pady=(0, 15))
        self._add_hover_effect(register_btn, self.styles["accent"], "#558cc9")

        # Back to Login Button - Centered
        back_btn = tk.Button(button_frame, text="← Back to Login", font=("Segoe UI", 12, "bold"), 
                            bg=self.styles["panel_bg"], fg=self.styles["accent"], 
                            relief="flat", cursor="hand2", padx=20, pady=8,
                            command=self.show_login_frame)
        back_btn.pack()
        self._add_hover_effect(back_btn, self.styles["panel_bg"], "#3d3d3d")

        # Set focus to first field
        self.reg_username.focus_set()

    def register(self):
        """Handle user registration"""
        username = self.reg_username.get().strip()
        email = self.reg_email.get().strip()
        password = self.reg_password.get()
        confirm_password = self.reg_confirm_password.get()
        security_question = self.security_question.get()
        security_answer = self.security_answer.get().strip()

        if not all([username, email, password, confirm_password, security_question, security_answer]):
            messagebox.showerror("Error", "All fields are required")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            messagebox.showerror("Error", "Invalid email format")
            return

        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters")
            return

        success, message = self.auth_manager.register(username, email, password, confirm_password, security_question, security_answer)
        if success:
            messagebox.showinfo("Success", message)
            self.show_login_frame()
        else:
            messagebox.showerror("Registration Failed", message)

    # ---------------- FORGOT PASSWORD ----------------
    def show_forgot_password_frame(self):
        self.clear_frame()
        self.current_frame = tk.Frame(self.root, bg=self.styles["bg"], padx=40, pady=40)
        self.current_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_frame = tk.Frame(self.current_frame, bg=self.styles["bg"])
        title_frame.pack(pady=(0, 30))
        
        tk.Label(title_frame, text="🔑", font=("Arial", 48), 
                bg=self.styles["bg"], fg=self.styles["accent"]).pack()
        
        tk.Label(title_frame, text="Reset Password", 
                font=("Segoe UI", 28, "bold"), bg=self.styles["bg"], fg=self.styles["fg"]).pack(pady=(10, 5))
        
        tk.Label(title_frame, text="Enter your registered email to receive password reset link", 
                font=("Segoe UI", 12), bg=self.styles["bg"], fg=self.styles["text_muted"]).pack()

        # Main container for centering
        main_container = tk.Frame(self.current_frame, bg=self.styles["bg"])
        main_container.pack(expand=True, fill=tk.BOTH)

        # Center frame
        center_frame = tk.Frame(main_container, bg=self.styles["bg"])
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Reset Form
        form_frame = tk.Frame(center_frame, bg=self.styles["panel_bg"], padx=40, pady=40,
                            highlightthickness=2, highlightbackground=self.styles["accent"])
        form_frame.pack(padx=20, pady=20)

        # Email Entry
        tk.Label(form_frame, text="Registered Email *", font=("Segoe UI", 12, "bold"),
                bg=self.styles["panel_bg"], fg=self.styles["fg"]).pack(anchor="w", pady=(0, 10))
        
        self.reset_email = tk.Entry(form_frame, font=("Segoe UI", 12), width=30, bg="#3d3d3d", fg="white",
                                insertbackground="white", relief="flat")
        self.reset_email.pack(fill=tk.X, pady=(0, 30))
        
        # Info text
        info_label = tk.Label(form_frame, 
                            text="A password reset email with instructions will be sent to your email address.\nCheck your inbox and follow the instructions to reset your password.",
                            font=("Segoe UI", 10), bg=self.styles["panel_bg"], fg=self.styles["text_muted"],
                            wraplength=300, justify="center")
        info_label.pack(pady=(0, 20))

        # Send Reset Link Button
        send_btn = tk.Button(form_frame, text="Send Reset Link", font=("Segoe UI", 12, "bold"),
                            bg=self.styles["secondary"], fg="white", relief="flat", cursor="hand2",
                            command=self.send_reset_link, width=20, height=2)
        send_btn.pack(pady=(10, 20))
        self._add_hover_effect(send_btn, self.styles["secondary"], "#45b7a8")

        # Back to Login
        back_btn = tk.Button(form_frame, text="← Back to Login", font=("Segoe UI", 11, "bold"), 
                            bg=self.styles["panel_bg"], fg=self.styles["accent"], 
                            relief="flat", cursor="hand2", padx=20, pady=6,
                            command=self.show_login_frame)
        back_btn.pack()
        self._add_hover_effect(back_btn, self.styles["panel_bg"], "#3d3d3d")

    def send_reset_link(self):
        """Send password reset link to user's email"""
        email = self.reset_email.get().strip()
        
        if not email:
            messagebox.showerror("Error", "Please enter your email address")
            return
        
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            messagebox.showerror("Error", "Invalid email format")
            return
        
        # Show loading state
        self.progress_label = tk.Label(self.current_frame, text="Sending reset email...", 
                                      font=("Segoe UI", 10), bg=self.styles["panel_bg"], fg=self.styles["accent"])
        self.progress_label.pack(pady=10)
        self.current_frame.update()
        
        try:
            # Check if email exists and send reset link
            success, message = self.auth_manager.initiate_password_reset(email)
            
            if success:
                messagebox.showinfo("Reset Email Sent", 
                                  f"Password reset instructions have been sent to:\n{email}\n\n"
                                  f"Please check your email and follow the instructions to reset your password.")
                
                # Show token entry window
                self.show_token_entry_window(email)
            else:
                messagebox.showerror("Error", message)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send reset email: {str(e)}")
        finally:
            if hasattr(self, 'progress_label'):
                self.progress_label.destroy()

    def show_token_entry_window(self, email):
        """Show window to enter reset token and new password with scrollbar"""
        token_win = tk.Toplevel(self.root)
        token_win.title("Reset Password")
        token_win.geometry("500x400")  # Fixed size
        token_win.configure(bg=self.styles["bg"])
        token_win.resizable(True, True)  # Allow resizing
        
        token_win.transient(self.root)
        token_win.grab_set()
        
        # Create main container with scrollbar
        main_container = tk.Frame(token_win, bg=self.styles["bg"])
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create canvas and scrollbar
        canvas = tk.Canvas(main_container, bg=self.styles["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.styles["bg"])
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind mousewheel to scroll
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Content frame inside scrollable frame
        content_frame = tk.Frame(scrollable_frame, bg=self.styles["bg"], padx=20, pady=20)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_frame = tk.Frame(content_frame, bg=self.styles["bg"])
        title_frame.pack(pady=(0, 20))
        
        tk.Label(title_frame, text="🔑", font=("Arial", 36), 
                bg=self.styles["bg"], fg=self.styles["accent"]).pack()
        
        tk.Label(title_frame, text="Reset Your Password", 
                font=("Segoe UI", 20, "bold"), bg=self.styles["bg"], fg=self.styles["fg"]).pack(pady=(10, 5))
        
        tk.Label(title_frame, text=f"Check your email: {email}", 
                font=("Segoe UI", 10), bg=self.styles["bg"], fg=self.styles["text_muted"]).pack()

        # Token Form
        form_frame = tk.Frame(content_frame, bg=self.styles["panel_bg"], padx=30, pady=30)
        form_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Token Entry
        tk.Label(form_frame, text="Reset Token *", font=("Segoe UI", 11, "bold"),
                bg=self.styles["panel_bg"], fg=self.styles["fg"]).pack(anchor="w", pady=(0, 5))
        token_entry = tk.Entry(form_frame, font=("Segoe UI", 12), width=30, 
                            bg="#3d3d3d", fg="white", insertbackground="white", relief="flat")
        token_entry.pack(fill=tk.X, pady=(0, 15))

        # New Password
        tk.Label(form_frame, text="New Password *", font=("Segoe UI", 11, "bold"),
                bg=self.styles["panel_bg"], fg=self.styles["fg"]).pack(anchor="w", pady=(0, 5))
        new_password_entry = tk.Entry(form_frame, font=("Segoe UI", 12), width=30, show="•", 
                                    bg="#3d3d3d", fg="white", insertbackground="white", relief="flat")
        new_password_entry.pack(fill=tk.X, pady=(0, 15))

        # Confirm New Password
        tk.Label(form_frame, text="Confirm New Password *", font=("Segoe UI", 11, "bold"),
                bg=self.styles["panel_bg"], fg=self.styles["fg"]).pack(anchor="w", pady=(0, 5))
        confirm_password_entry = tk.Entry(form_frame, font=("Segoe UI", 12), width=30, show="•", 
                                        bg="#3d3d3d", fg="white", insertbackground="white", relief="flat")
        confirm_password_entry.pack(fill=tk.X, pady=(0, 15))

        # Password strength indicator
        self.token_strength_label = tk.Label(form_frame, text="Password strength: Not assessed", 
                                            font=("Segoe UI", 9), bg=self.styles["panel_bg"], fg="#666666")
        self.token_strength_label.pack(anchor="w", pady=(0, 10))

        # Add real-time password strength assessment
        def update_password_strength(event=None):
            password = new_password_entry.get()
            if password:
                # Simple password strength check
                score = 0
                if len(password) >= 8:
                    score += 1
                if any(c.isupper() for c in password):
                    score += 1
                if any(c.islower() for c in password):
                    score += 1
                if any(c.isdigit() for c in password):
                    score += 1
                if any(not c.isalnum() for c in password):
                    score += 1
                
                if score >= 5:
                    message = "Strong password"
                    color = "#2a9d8f"
                elif score >= 3:
                    message = "Medium strength"
                    color = "#e9c46a"
                else:
                    message = "Weak password"
                    color = "#e76f51"
                
                self.token_strength_label.config(text=f"Password strength: {message}", fg=color)
            else:
                self.token_strength_label.config(text="Password strength: Not assessed", fg="#666666")

        new_password_entry.bind('<KeyRelease>', update_password_strength)

        # Show password checkbox
        show_pass_var = tk.BooleanVar()
        show_pass_check = tk.Checkbutton(form_frame, text="Show passwords", variable=show_pass_var,
                                        bg=self.styles["panel_bg"], fg=self.styles["fg"], 
                                        font=("Segoe UI", 9),
                                        command=lambda: self.toggle_passwords_visibility(
                                            new_password_entry, confirm_password_entry, show_pass_var))
        show_pass_check.pack(anchor="w", pady=(0, 20))

        # Reset Button
        def perform_reset():
            token = token_entry.get().strip()
            new_pass = new_password_entry.get()
            confirm_pass = confirm_password_entry.get()
            
            if not token:
                messagebox.showerror("Error", "Please enter the reset token from your email")
                return
            
            if not new_pass or not confirm_pass:
                messagebox.showerror("Error", "Please enter both password fields")
                return
            
            if new_pass != confirm_pass:
                messagebox.showerror("Error", "Passwords do not match")
                return
            
            if len(new_pass) < 6:
                messagebox.showerror("Error", "Password must be at least 6 characters")
                return
            
            # Reset password using token
            success, message = self.auth_manager.verify_token_and_reset(token, new_pass, confirm_pass)
            if success:
                messagebox.showinfo("Success", "Password reset successfully! You can now login with your new password.")
                token_win.destroy()
                self.show_login_frame()
            else:
                messagebox.showerror("Error", message)

        reset_btn = tk.Button(form_frame, text="Reset Password", font=("Segoe UI", 12, "bold"),
                            bg=self.styles["secondary"], fg="white", relief="flat", cursor="hand2",
                            command=perform_reset, width=20, height=2)
        reset_btn.pack(pady=(10, 15))
        self._add_hover_effect(reset_btn, self.styles["secondary"], "#45b7a8")

        # Back button
        back_btn = tk.Button(form_frame, text="← Back", font=("Segoe UI", 10), 
                            bg=self.styles["panel_bg"], fg=self.styles["accent"], 
                            relief="flat", cursor="hand2",
                            command=token_win.destroy)
        back_btn.pack()
        self._add_hover_effect(back_btn, self.styles["panel_bg"], "#3d3d3d")

        # Set focus to token entry
        token_entry.focus_set()
        
        # Update the scrollregion after everything is drawn
        token_win.update()
        canvas.configure(scrollregion=canvas.bbox("all"))

    def _add_hover_effect(self, widget, normal_bg, hover_bg):
        """Add hover effect to buttons"""
        widget.bind("<Enter>", lambda e: widget.config(bg=hover_bg))
        widget.bind("<Leave>", lambda e: widget.config(bg=normal_bg))

    def toggle_passwords_visibility(self, password_entry, confirm_entry, show_var):
        """Toggle password visibility for both password fields"""
        if show_var.get():
            password_entry.config(show="")
            confirm_entry.config(show="")
        else:
            password_entry.config(show="•")
            confirm_entry.config(show="•")

# ==================== MAIN APPLICATION ====================
class FolderEncryptorGUI:
    def __init__(self, root, auth_manager):
        self.root = root
        self.auth_manager = auth_manager
        
        # Check authentication
        current_user = self.auth_manager.get_current_user()
        print(f"🔍 User authenticated: {current_user}")
        
        if not current_user:
            messagebox.showerror("Error", "Not authenticated properly!")
            self.root.destroy()
            return
        
        self.root.title("Secure Folder Encryption & Decryption")
        self.root.state("zoomed")
        
        # Initialize managers
        self.asset_manager = AssetManager()
        self.logger = EncryptionLogger()
        self.validator = InputValidator()
        self.password_manager = PasswordManager()
        self.theme_manager = ThemeManager()
        
        self.bg_label = None
        self.bg_photo = None
        self._set_background()
        self.root.bind("<Configure>", self._resize_bg)
        self._build_interface()

    # ------------------- BACKGROUND ------------------- #
    def _set_background(self):
        """Set the background image with proper error handling"""
        try:
            # First set a solid background
            self.root.configure(bg="#1e1e1e")
            
            background_path = self.asset_manager.get_background_path()
            print(f"🖼️ Loading background from: {background_path}")
            
            if os.path.exists(background_path):
                # Load and resize image
                img = Image.open(background_path).convert("RGBA")
                win_w, win_h = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
                img = img.resize((win_w, win_h), Image.LANCZOS)
                self.bg_photo = ImageTk.PhotoImage(img)
                
                # Create background label
                self.bg_label = tk.Label(self.root, image=self.bg_photo)
                self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
                self.bg_label.lower()  # Send to back
                
                print("✅ Background loaded successfully")
            else:
                print("⚠️ Background image not found, using solid color")
                
        except Exception as e:
            print(f"❌ Failed to load background: {e}")
            # Keep the solid background
            self.root.configure(bg="#1e1e1e")
    def _set_fallback_background(self):
        """Set a fallback background if image loading fails"""
        try:
            self.root.configure(bg="#101010")
            if self.bg_label:
                self.bg_label.destroy()
                self.bg_label = None
            print("✅ Using fallback solid color background")
        except Exception as e:
            print(f"❌ Fallback background failed: {e}")

    def _resize_bg(self, event):
        """Resize background when window size changes"""
        if event.widget == self.root:  # Only respond to root window resize
            try:
                background_path = self.asset_manager.current_background_path
                if background_path and os.path.exists(background_path):
                    img = Image.open(background_path).convert("RGBA")
                    img = img.resize((event.width, event.height), Image.LANCZOS)
                    self.bg_photo = ImageTk.PhotoImage(img)
                    if self.bg_label:
                        self.bg_label.configure(image=self.bg_photo)
            except Exception as e:
                print(f"❌ Failed to resize background: {e}")

    def select_custom_background(self):
        """Let user select a custom background image"""
        file_types = [
            ("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"),
            ("All files", "*.*")
        ]
        
        file_path = filedialog.askopenfilename(
            title="Select Background Image",
            filetypes=file_types
        )
        
        if file_path:
            try:
                # Set custom background using asset manager
                success = self.asset_manager.set_custom_background(file_path)
                if success:
                    # Update the background
                    self._set_background()
                    messagebox.showinfo("Success", "Background updated successfully!")
                else:
                    messagebox.showerror("Error", "Failed to set background image")
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to set background: {str(e)}")

    # ------------------- INTERFACE ------------------- #
    def _build_interface(self):
        # User info and logout button
        user_frame = tk.Frame(self.root, bg="#1e1e1e", padx=10, pady=5)
        user_frame.place(relx=0.02, rely=0.02, anchor="nw")
        
        current_user = self.auth_manager.get_current_user()
        user_label = tk.Label(user_frame, text=f"👤 {current_user}", font=("Segoe UI", 10, "bold"),
                             bg="#1e1e1e", fg="#ffffff")
        user_label.pack(side=tk.LEFT)
        
        logout_btn = tk.Button(user_frame, text="Logout", font=("Segoe UI", 9),
                              bg="#e74c3c", fg="white", relief="flat", cursor="hand2",
                              command=self.logout)
        logout_btn.pack(side=tk.LEFT, padx=(10, 0))
        self._add_hover(logout_btn, normal_bg="#e74c3c", hover_bg="#c0392b")

        # Theme Toggle Button
        theme_btn = tk.Button(
            self.root,
            text="🌓 Toggle Theme",
            font=("Segoe UI", 10),
            bg="#3a6ea5", fg="white",
            command=self.toggle_theme
        )
        theme_btn.place(relx=0.95, rely=0.02, anchor="ne")
        self._add_hover(theme_btn, normal_bg="#3a6ea5", hover_bg="#558cc9")

        # Background Selector Button
        bg_btn = tk.Button(
            self.root,
            text="🎨 Change Background",
            font=("Segoe UI", 10),
            bg="#6a3ea5", fg="white",
            command=self.select_custom_background
        )
        bg_btn.place(relx=0.95, rely=0.07, anchor="ne")
        self._add_hover(bg_btn, normal_bg="#6a3ea5", hover_bg="#8a5ec5")

        # Project Info button
        top_frame = tk.Frame(self.root, bg="#1e1e1e", padx=0, pady=8)
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
        theme = self.theme_manager.get_theme()
        panel_bg = theme["panel_bg"]
        panel_border = theme["border"]
        container = tk.Frame(
            self.root, bg=panel_bg, bd=0,
            highlightthickness=2, highlightbackground=panel_border,
            padx=16, pady=12
        )
        container.place(relx=0.75, rely=0.2, relwidth=0.35, relheight=0.6, anchor="n")

        title = tk.Label(container, text="Secure Folder Encryption", font=("Segoe UI", 16, "bold"),
                         fg=theme["fg"], bg=panel_bg)
        title.pack(pady=(6,6))

        subtitle = tk.Label(container, text="AES-256-GCM • PBKDF2 • Secure Email Delivery",
                            font=("Segoe UI", 9), fg=theme["text_muted"], bg=panel_bg)
        subtitle.pack(pady=(0,10))

        self._load_icon(container)

        # Buttons
        btn_frame = tk.Frame(container, bg=panel_bg)
        btn_frame.pack(pady=8)
        
        # Encrypt Button
        encrypt_btn = tk.Button(btn_frame, text="Encrypt Folder", font=("Segoe UI", 11, "bold"),
                                bg=theme["button_bg"], fg=theme["button_fg"], width=18, height=2,
                                command=self.encrypt_window)
        encrypt_btn.grid(row=0, column=0, padx=8, pady=6)
        self._add_hover(encrypt_btn, normal_bg=theme["button_bg"], hover_bg="#558cc9")

        # Decrypt Button
        decrypt_btn = tk.Button(btn_frame, text="Decrypt Folder", font=("Segoe UI", 11, "bold"),
                                bg="#2a9d8f", fg="white", width=18, height=2,
                                command=self.decrypt_window)
        decrypt_btn.grid(row=1, column=0, padx=8, pady=6)
        self._add_hover(decrypt_btn, normal_bg="#2a9d8f", hover_bg="#45b7a8")

        foot = tk.Label(container, text="Tip: Use strong passphrases & test on copies.",
                        font=("Segoe UI", 8), fg=theme["text_muted"], bg=panel_bg)
        foot.pack(side="bottom", pady=(8,2))

    def logout(self):
        """Logout user and return to authentication"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self.auth_manager.logout()
            self.root.destroy()
            # Restart the application with authentication
            start_authentication()

    def toggle_theme(self):
        new_theme = self.theme_manager.toggle_theme()
        self._rebuild_interface_with_theme(new_theme)

    def _rebuild_interface_with_theme(self, theme):
        # Clear existing widgets and rebuild with new theme
        for widget in self.root.winfo_children():
            if not isinstance(widget, tk.Label) or widget != self.bg_label:
                widget.destroy()
        self._build_interface()

    # ------------------- ICON ------------------- #
    def _load_icon(self, parent):
        # Look for icon in base directory
        for ext in ("png", "jpg", "jpeg", "ico"):
            icon_path = os.path.join(BASE_PATH, f"image.{ext}")
            if os.path.exists(icon_path):
                try:
                    img = Image.open(icon_path).convert("RGBA").resize((90,90), Image.LANCZOS)
                    self.folder_icon = ImageTk.PhotoImage(img)
                    tk.Label(parent, image=self.folder_icon, bg=parent["bg"], bd=0).pack(pady=5)
                    return
                except Exception as e:
                    print(f"Error loading icon: {e}")
        
        # Fallback to emoji
        tk.Label(parent, text="🔒", font=("Segoe UI",48), fg="#3a6ea5", bg=parent["bg"]).pack(pady=5)

    # ------------------- HOVER ------------------- #
    def _add_hover(self, widget, normal_bg, hover_bg):
        widget.bind("<Enter>", lambda e: widget.config(bg=hover_bg))
        widget.bind("<Leave>", lambda e: widget.config(bg=normal_bg))

    # ------------------- PROJECT INFO ------------------- #
    def open_about(self):
        # Download or get Supraja Technologies logo
        logo_path = self.asset_manager.download_supraja_logo()
        circular_logo_path = None
        
        # Create circular version of the logo
        if logo_path and os.path.exists(logo_path):
            try:
                # Create circular logo
                img = Image.open(logo_path).convert("RGBA")
                img = img.resize((120, 120), Image.LANCZOS)
                
                # Create circular mask
                mask = Image.new('L', (120, 120), 0)
                draw = ImageDraw.Draw(mask)
                draw.ellipse((0, 0, 120, 120), fill=255)
                
                # Apply mask
                result = Image.new('RGBA', (120, 120), (0, 0, 0, 0))
                result.putalpha(mask)
                result.paste(img, (0, 0), mask)
                
                # Save to temp file
                temp_dir = tempfile.gettempdir()
                circular_logo_path = os.path.join(temp_dir, f"supraja_circular_logo_{int(time.time())}.png")
                result.save(circular_logo_path)
                
                # Convert to absolute path for HTML
                circular_logo_abs_path = circular_logo_path.replace('\\', '/')
                logo_src = f"file:///{circular_logo_abs_path}"
                
            except Exception as e:
                print(f"Logo processing error: {e}")
                logo_src = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIwIiBoZWlnaHQ9IjEyMCIgdmlld0JveD0iMCAwIDEyMCAxMjAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxMjAiIGhlaWdodD0iMTIwIiByeD0iNjAiIGZpbGw9IiMzYTZlYTUiLz4KPHRleHQgeD0iNjAiIHk9IjY4IiBmb250LWZhbWlseT0iQXJpYWwiIGZvbnQtc2l6ZT0iMjQiIGZpbGw9IndoaXRlIiB0ZXh0LWFuY2hvcj9taWRkbGUiIGZvbnQtd2VpZ2h0PSJib2xkIj5TVDwvdGV4dD4KPC9zdmc+Cg=="
        else:
            # Use fallback base64 encoded logo
            logo_src = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIwIiBoZWlnaHQ9IjEyMCIgdmlld0JveD0iMCAwIDEyMCAxMjAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxMjAiIGhlaWdodD0iMTIwIiByeD0iNjAiIGZpbGw9IiMzYTZlYTUiLz4KPHRleHQgeD0iNjAiIHk9IjY4IiBmb250LWZhbWlseT0iQXJpYWwiIGZvbnQtc2l6ZT0iMjQiIGZpbGw9IndoaXRlIiB0ZXh0LWFuY2hvcj9taWRkbGUiIGZvbnQtd2VpZ2h0PSJib2xkIj5TVDwvdGV4dD4KPC9zdmc+Cg=="

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Project Information - Supraja Technologies</title>
<style>
body {{
    font-family: 'Segoe UI', Arial, sans-serif; 
    margin: 40px; 
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: #333;
    line-height: 1.6;
}}
.container {{
    max-width: 1000px;
    margin: 0 auto;
    background: white;
    padding: 40px;
    border-radius: 15px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
    position: relative;
}}
h1 {{
    font-size: 32px; 
    margin-top: 20px;
    margin-bottom: 10px;
    color: #2c3e50;
    text-align: center;
}}
p {{
    font-size: 16px; 
    line-height: 1.6; 
    margin-top: 20px;
    text-align: center;
}}
table {{
    border-collapse: collapse; 
    width: 100%; 
    margin-top: 20px; 
    background: #fff;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}}
table, th, td {{
    border: 1px solid #ddd;
}}
th, td {{
    padding: 12px; 
    text-align: left;
}}
th {{
    background: #3a6ea5; 
    color: white;
    font-weight: bold;
}}
.section-title {{
    margin-top: 30px; 
    font-size: 22px; 
    font-weight: bold;
    color: #3a6ea5;
    border-bottom: 2px solid #3a6ea5;
    padding-bottom: 5px;
}}
.logo {{
    position: absolute;
    top: 20px;
    right: 40px;
    width: 120px;
    height: 120px;
    border-radius: 50%;
    border: 4px solid #3a6ea5;
    box-shadow: 0 4px 8px rgba(0,0,0,0.2);
}}
.header {{
    text-align: center;
    margin-bottom: 30px;
    padding-bottom: 20px;
    border-bottom: 3px solid #3a6ea5;
}}
.company-name {{
    font-size: 24px;
    font-weight: bold;
    color: #3a6ea5;
    margin-top: 10px;
}}
.features-grid {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
    margin-top: 15px;
}}
.feature-item {{
    background: #f8f9fa;
    padding: 8px 12px;
    border-radius: 5px;
    border-left: 4px solid #3a6ea5;
}}
.highlight {{
    background: linear-gradient(120deg, #a8edea 0%, #fed6e3 100%);
    padding: 20px;
    border-radius: 10px;
    margin: 20px 0;
    text-align: center;
    border: 2px solid #3a6ea5;
}}
</style>
</head>
<body>
<div class="container">
    <img src="{logo_src}" alt="Supraja Technologies Logo" class="logo">
    
    <div class="header">
        <div class="company-name">Supraja Technologies</div>
        <h1>Project Information</h1>
    </div>

    <div class="highlight">
        <p>This project was developed by <b>Siri, Tasleem, Bhavya, Manasa</b> as part of a 
        <b>Cyber Security Internship</b> at <b>Supraja Technologies</b>. This project is designed to 
        <b>Secure Organizations in Real World from Cyber Frauds performed by Hackers.</b></p>
    </div>

    <div class="section-title">Project Details</div>
    <table>
    <tr><th>Project Details</th><th>Value</th></tr>
    <tr><td>Project Name</td><td>Enhanced Folder Encryption & Decryption</td></tr>
    <tr><td>Project Description</td><td>Advanced Secure Encryption with Multi-Platform Support</td></tr>
    <tr><td>Project Start Date</td><td>26-AUG-2025</td></tr>
    <tr><td>Project End Date</td><td>10-OCT-2025</td></tr>
    <tr><td>Project Status</td><td><b>Completed with Enhanced Features</b></td></tr>
    <tr><td>Technology Stack</td><td>Python, TKinter, AES-256, PBKDF2, SMTP</td></tr>
    </table>

    <div class="section-title">Enhanced Features</div>
    <div class="features-grid">
        <div class="feature-item">Multi-Platform Asset Management</div>
        <div class="feature-item">Comprehensive Logging System</div>
        <div class="feature-item">Advanced Input Validation</div>
        <div class="feature-item">Password Strength Assessment</div>
        <div class="feature-item">Dark/Light Theme Support</div>
        <div class="feature-item">Professional Error Handling</div>
        <div class="feature-item">Custom Background Support</div>
        <div class="feature-item">Secure Email Delivery</div>
    </div>

    <div class="section-title">Developer Details</div>
    <table>
    <tr><th>Name</th><td>E. SIRI</td></tr>
    <tr><th>Employee ID</th><td>23WH1A0512</td></tr>
    <tr><th>Email</th><td>23wh1a0512@bvrithyderabad.edu.in</td></tr>
    <tr><th>Role</th><td>Lead Developer</td></tr>
    
    <tr><th>Name</th><td>SK. TASLEEM</td></tr>
    <tr><th>Employee ID</th><td>23WH1A0541</td></tr>
    <tr><th>Email</th><td>23wh1a0541@bvrithyderabad.edu.in</td></tr>
    <tr><th>Role</th><td>Security Specialist</td></tr>
    
    <tr><th>Name</th><td>A. BHAVYA</td></tr>
    <tr><th>Employee ID</th><td>23WH1A0581</td></tr>
    <tr><th>Email</th><td>23wh1a0581@bvrithyderabad.edu.in</td></tr>
    <tr><th>Role</th><td>UI/UX Designer</td></tr>
    
    <tr><th>Name</th><td>MANASA</td></tr>
    <tr><th>Employee ID</th><td>23WH1A0585</td></tr>
    <tr><th>Email</th><td>23wh1a0585@bvrithyderabad.edu.in</td></tr>
    <tr><th>Role</th><td>Testing & Documentation</td></tr>
    </table>

    <div class="section-title">Company Details</div>
    <table>
    <tr><th>Company</th><td>Supraja Technologies</td></tr>
    <tr><th>Email</th><td>contact@suprajatechnologies.com</td></tr>
    <tr><th>Website</th><td>www.suprajatechnologies.com</td></tr>
    <tr><th>Industry</th><td>Information Technology & Services</td></tr>
    <tr><th>Specialization</th><td>Cyber Security, Software Development, Internship Programs</td></tr>
    </table>

    <div style="text-align: center; margin-top: 30px; padding: 15px; background: #f8f9fa; border-radius: 8px;">
        <strong>© 2025 Supraja Technologies. All Rights Reserved.</strong><br>
        <em>Empowering the next generation of cybersecurity professionals</em>
    </div>
</div>
</body>
</html>"""
        
        # Create and open HTML file
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode='w', encoding='utf-8')
        tmp_file.write(html_content)
        tmp_file.name
        tmp_file.close()
        webbrowser.open(f"file://{tmp_file.name}")

    # ------------------- ENCRYPT WINDOW ------------------- #
    def encrypt_window(self):
        self.encrypt_win = tk.Toplevel(self.root)
        self.encrypt_win.title("Encrypt Folder")
        self.encrypt_win.geometry("600x600")
        self.encrypt_win.configure(bg="#f0f0f0")
        self.encrypt_win.resizable(False, False)
        
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

        # Password strength indicator
        strength_frame = tk.Frame(main_frame, bg="#f0f0f0")
        strength_frame.pack(fill=tk.X, pady=5)
        
        self.strength_label = tk.Label(strength_frame, text="Password strength: Not generated", 
                                      bg="#f0f0f0", font=("Segoe UI", 9))
        self.strength_label.pack(anchor="w")

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
        
        # Enhanced validation
        is_valid, message = self.validator.validate_folder_path(folder_path)
        if not is_valid:
            messagebox.showerror("Validation Error", f"Folder Error: {message}")
            return
        
        is_valid, message = self.validator.validate_email_address(sender)
        if not is_valid:
            messagebox.showerror("Validation Error", f"Sender Email: {message}")
            return
        
        is_valid, message = self.validator.validate_email_address(receiver)
        if not is_valid:
            messagebox.showerror("Validation Error", f"Receiver Email: {message}")
            return
        
        if not smtp_pass:
            messagebox.showerror("Error", "SMTP password is required")
            return
        
        # Disable button and start progress
        self.progress['value'] = 0
        self.progress_label.config(text="Starting encryption process...")
        self.encrypt_win.update()
            
        # Run encryption
        self.encrypt_win.after(100, lambda: self.encrypt_folder(folder_path, sender, smtp_pass, receiver))

    # ------------------- DECRYPT WINDOW ------------------- #
    def decrypt_window(self):
        self.decrypt_win = tk.Toplevel(self.root)
        self.decrypt_win.title("Decrypt Folder")
        self.decrypt_win.geometry("500x500")
        self.decrypt_win.configure(bg="#f0f0f0")
        self.decrypt_win.resizable(False, False)
        
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

        # Password entry with strength indicator
        tk.Label(main_frame, text="Decryption Password:", bg="#f0f0f0", 
                font=("Segoe UI", 10)).pack(anchor="w", pady=(15, 0))
        self.password_entry = tk.Entry(main_frame, width=50, show="*", font=("Segoe UI", 10))
        self.password_entry.pack(fill=tk.X, pady=5)

        # Password strength indicator
        self.decrypt_strength_label = tk.Label(main_frame, text="Password strength: Not assessed", 
                                              bg="#f0f0f0", font=("Segoe UI", 9))
        self.decrypt_strength_label.pack(anchor="w", pady=2)
        
        # Add real-time password strength assessment
        self.password_entry.bind('<KeyRelease>', self._update_decrypt_password_strength)

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

    def _update_decrypt_password_strength(self, event=None):
        password = self.password_entry.get()
        if password:
            score, message = self.password_manager.assess_password_strength(password)
            if score >= 5:
                color = "#2a9d8f"
            elif score >= 3:
                color = "#e9c46a"
            else:
                color = "#e76f51"
            self.decrypt_strength_label.config(text=f"Password strength: {message}", fg=color)
        else:
            self.decrypt_strength_label.config(text="Password strength: Not assessed", fg="#666666")

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
        
        # Enhanced validation
        is_valid, message = self.validator.validate_folder_path(folder_path)
        if not is_valid:
            messagebox.showerror("Validation Error", f"Folder Error: {message}")
            return
        
        if not password:
            messagebox.showerror("Error", "Password is required")
            return
        
        # Validate password strength
        is_valid, message = self.validator.validate_password_strength(password)
        if not is_valid:
            if not messagebox.askyesno("Weak Password", f"{message}\nContinue anyway?"):
                return
        
        # Disable button and start progress
        self.decrypt_progress['value'] = 0
        self.decrypt_progress_label.config(text="Starting decryption process...")
        self.decrypt_win.update()
            
        # Run decryption
        self.decrypt_win.after(100, lambda: self.decrypt_folder(folder_path, password))

    # ------------------- ENCRYPTION/DECRYPTION LOGIC ------------------- #
    def encrypt_folder(self, folder_path, sender, smtp_pass, receiver):
        try:
            # Log the operation start
            self.logger.log_encryption_start(folder_path, 0)
            
            # Generate a secure password
            password = self.password_manager.generate_strong_password()
            
            # Update password strength display
            score, message = self.password_manager.assess_password_strength(password)
            if hasattr(self, 'strength_label'):
                self.strength_label.config(text=f"Generated password: {message}", fg="#2a9d8f")
            
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
                self.logger.log_error("email_send", str(email_error), folder_path)
                messagebox.showwarning("Email Warning", f"Encryption completed but email failed: {email_error}")
            
            # Complete progress and log success
            self.progress['value'] = 100
            self.progress_label.config(text="Encryption completed successfully!")
            self.encrypt_win.update()
            self.logger.log_encryption_complete(folder_path, encrypted_files, file_count)
            
            time.sleep(1)
            
            # Show success message
            self.encrypt_win.destroy()
            
            success_message = f"""✅ FOLDER ENCRYPTION SUCCESSFUL!

📁 Folder: {os.path.basename(folder_path)}
📊 Files Encrypted: {file_count}
📧 Password sent to: {receiver}
🔒 Password Strength: {message}

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
            self.logger.log_error("encryption", str(e), folder_path)
            print(f"❌ ENCRYPTION ERROR: {str(e)}")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_folder(self, folder_path, password):
        try:
            self.logger.log_decryption_attempt(folder_path, False)  # Start as not successful
            
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
                original_file_path = encrypted_file_path[:-4]
                
                # Decrypt the file
                self.aes_decrypt(encrypted_file_path, original_file_path, password)
                
                # Remove the encrypted file after successful decryption
                os.remove(encrypted_file_path)
                decrypted_files += 1
            
            # Update progress and log success
            self.decrypt_progress['value'] = 100
            self.decrypt_progress_label.config(text="Decryption completed successfully!")
            self.decrypt_win.update()
            self.logger.log_decryption_attempt(folder_path, True)
            
            time.sleep(1)
            
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
            self.logger.log_error("decryption", str(e), folder_path)
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

# ==================== APPLICATION STARTUP ====================

# Global auth manager
auth_manager = AuthManager()

def start_application():
    """Start the main application"""
    print("🚀 Starting Main Application...")
    root = tk.Tk()
    app = FolderEncryptorGUI(root, auth_manager)
    root.mainloop()

def start_authentication():
    """Start the authentication system"""
    print("🔐 Starting Authentication...")
    auth_root = tk.Tk()
    auth_gui = AuthGUI(auth_root, auth_manager)
    auth_root.mainloop()

# Set login callback
def on_login_success():
    """Callback function when login is successful"""
    print("✅ Login successful! Launching main application...")
    start_application()

auth_manager.set_login_callback(on_login_success)

# ------------------- RUN APP ------------------- #
if __name__ == "__main__":
    # Start with authentication
    print(f"🚀 Starting Secure Folder Encryption Application...")
    print(f"📁 Base Path: {BASE_PATH}")
    start_authentication()

