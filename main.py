import tkinter as tk
from tkinter import ttk, messagebox
from database import Database
from utils import generate_otp, send_otp_email
import bcrypt
import re
from tkinter import scrolledtext

class PasswordManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Manager")
        self.root.geometry("800x600")  # Tablet size
        self.root.configure(bg='#f0f0f0')
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure('TButton', padding=5, font=('Arial', 10))
        self.style.configure('TLabel', font=('Arial', 10))
        self.style.configure('TEntry', padding=5)
        self.style.configure('TLabelframe', background='#f0f0f0')
        self.style.configure('TLabelframe.Label', font=('Arial', 12, 'bold'))
        
        # Custom colors
        self.primary_color = '#4a90e2'
        self.secondary_color = '#f5f5f5'
        self.accent_color = '#2c3e50'
        
        self.db = Database()
        self.current_user = None
        self.show_login_page()

    def show_login_page(self):
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        title_label = ttk.Label(main_frame, text="Password Manager", font=('Arial', 24, 'bold'), foreground=self.primary_color)
        title_label.grid(row=0, column=0, columnspan=2, pady=20)
        
        frame = ttk.LabelFrame(main_frame, text="Login", padding="20")
        frame.grid(row=1, column=0, columnspan=2, pady=10, padx=10)
        
        ttk.Label(frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(frame, width=25)
        self.username_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(frame, show="*", width=25)
        self.password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(frame, text="Login", command=self.login, width=20).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(frame, text="Create Account", command=self.show_create_account_page, width=20).grid(row=3, column=0, columnspan=2, pady=5)
        ttk.Button(frame, text="Forgot Password", command=self.show_forgot_password_page, width=20).grid(row=4, column=0, columnspan=2, pady=5)
        ttk.Button(frame, text="Forgot Username", command=self.show_forgot_username_page, width=20).grid(row=5, column=0, columnspan=2, pady=5)

    def show_create_account_page(self):
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        title_label = ttk.Label(main_frame, text="Create Account", font=('Arial', 20, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=20)
        
        frame = ttk.LabelFrame(main_frame, text="Account Details", padding="20")
        frame.grid(row=1, column=0, columnspan=2, pady=10, padx=10)
        
        ttk.Label(frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.new_username_entry = ttk.Entry(frame, width=30)
        self.new_username_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(frame, text="Email:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.email_entry = ttk.Entry(frame, width=30)
        self.email_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.new_password_entry = ttk.Entry(frame, show="*", width=30)
        self.new_password_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(frame, text="Confirm Password:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.confirm_password_entry = ttk.Entry(frame, show="*", width=30)
        self.confirm_password_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(frame, text="Create Account", command=self.create_account, width=20).grid(row=4, column=0, columnspan=2, pady=10)
        ttk.Button(frame, text="Back to Login", command=self.show_login_page, width=20).grid(row=5, column=0, columnspan=2, pady=5)

    def show_forgot_username_page(self):
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        title_label = ttk.Label(main_frame, text="Forgot Username", font=('Arial', 20, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=20)
        
        frame = ttk.LabelFrame(main_frame, text="Recover Username", padding="20")
        frame.grid(row=1, column=0, columnspan=2, pady=10, padx=10)
        
        ttk.Label(frame, text="Email:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.forgot_username_email_entry = ttk.Entry(frame, width=30)
        self.forgot_username_email_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(frame, text="Send Username", command=self.send_username, width=20).grid(row=1, column=0, columnspan=2, pady=10)
        ttk.Button(frame, text="Back to Login", command=self.show_login_page, width=20).grid(row=2, column=0, columnspan=2, pady=5)

    def send_username(self):
        email = self.forgot_username_email_entry.get()
        user = self.db.get_user_by_email(email)
        
        if not user:
            messagebox.showerror("Error", "Email not found")
            return
        
        if send_otp_email(email, f"Your username is: {user['username']}"):
            messagebox.showinfo("Success", "Username sent to your email")
            self.show_login_page()
        else:
            messagebox.showerror("Error", "Failed to send email")

    def show_profile_page(self):
        self.clear_window()
        
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Back button at the top
        back_button = ttk.Button(main_frame, text="← Back to Dashboard", command=self.show_main_dashboard)
        back_button.grid(row=0, column=0, sticky=tk.W, pady=5)
        
        # Title
        title_label = ttk.Label(main_frame, text="User Profile", font=('Arial', 20, 'bold'))
        title_label.grid(row=1, column=0, columnspan=2, pady=10)
        
        # User Info Frame
        info_frame = ttk.LabelFrame(main_frame, text="User Information", padding="10")
        info_frame.grid(row=2, column=0, pady=5, padx=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Display user information
        ttk.Label(info_frame, text=f"Username: {self.current_user['username']}", font=('Arial', 12)).grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Label(info_frame, text=f"Email: {self.current_user['email']}", font=('Arial', 12)).grid(row=1, column=0, sticky=tk.W, pady=5)
        
        # Change Password Frame
        password_frame = ttk.LabelFrame(main_frame, text="Change Password", padding="10")
        password_frame.grid(row=3, column=0, pady=5, padx=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Current password
        ttk.Label(password_frame, text="Current Password:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.current_password_entry = ttk.Entry(password_frame, show="*")
        self.current_password_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # New password
        ttk.Label(password_frame, text="New Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.new_password_entry = ttk.Entry(password_frame, show="*")
        self.new_password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Confirm new password
        ttk.Label(password_frame, text="Confirm New Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.confirm_new_password_entry = ttk.Entry(password_frame, show="*")
        self.confirm_new_password_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Change password button
        change_password_button = ttk.Button(password_frame, text="Change Password", command=self.change_password)
        change_password_button.grid(row=3, column=0, columnspan=2, pady=10)
        
        # Delete account button
        delete_account_button = ttk.Button(main_frame, text="Delete Account", command=self.confirm_delete_account, style='Danger.TButton')
        delete_account_button.grid(row=4, column=0, pady=10)
        
        # Configure the danger style for the delete button
        style = ttk.Style()
        style.configure('Danger.TButton', 
            foreground='red', 
            font=('Arial', 12, 'bold'),
            padding=10
        )

    def change_password(self):
        current_password = self.current_password_entry.get()
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_new_password_entry.get()
        
        if not current_password or not new_password or not confirm_password:
            messagebox.showerror("Error", "All fields are required")
            return
        
        if new_password != confirm_password:
            messagebox.showerror("Error", "New passwords do not match")
            return
        
        # Verify current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), self.current_user['password']):
            messagebox.showerror("Error", "Current password is incorrect")
            return
        
        # Update password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        self.db.users.update_one(
            {'_id': self.current_user['_id']},
            {'$set': {'password': hashed_password}}
        )
        
        # Update current user
        self.current_user['password'] = hashed_password
        
        # Clear fields
        self.current_password_entry.delete(0, tk.END)
        self.new_password_entry.delete(0, tk.END)
        self.confirm_new_password_entry.delete(0, tk.END)
        
        messagebox.showinfo("Success", "Password changed successfully")

    def show_view_passwords_page(self):
        self.clear_window()
        
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Back button at the top
        back_button = ttk.Button(main_frame, text="← Back to Dashboard", command=self.show_main_dashboard)
        back_button.grid(row=0, column=0, sticky=tk.W, pady=5)
        
        # Title
        title_label = ttk.Label(main_frame, text="View Passwords", font=('Arial', 20, 'bold'))
        title_label.grid(row=1, column=0, columnspan=2, pady=10)
        
        # Search Frame
        search_frame = ttk.LabelFrame(main_frame, text="Search", padding="10")
        search_frame.grid(row=2, column=0, columnspan=2, pady=5, padx=5, sticky=(tk.W, tk.E))
        
        # Search entry and buttons
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, sticky=tk.W)
        self.search_entry = ttk.Entry(search_frame, width=30)
        self.search_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        
        # Add search button
        search_button = ttk.Button(search_frame, text="Search", command=self.perform_search)
        search_button.grid(row=0, column=2, padx=5)
        
        # Add clear button
        clear_button = ttk.Button(search_frame, text="Clear", command=self.clear_search)
        clear_button.grid(row=0, column=3, padx=5)
        
        # Bind Enter key to search
        self.search_entry.bind('<Return>', lambda e: self.perform_search())
        
        # App Passwords Frame
        app_frame = ttk.LabelFrame(main_frame, text="App Passwords", padding="10")
        app_frame.grid(row=3, column=0, pady=5, padx=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create a frame for the app treeview and scrollbar
        app_tree_frame = ttk.Frame(app_frame)
        app_tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create a canvas and scrollbar for app passwords
        app_canvas = tk.Canvas(app_tree_frame)
        app_scrollbar = ttk.Scrollbar(app_tree_frame, orient="vertical", command=app_canvas.yview)
        app_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.app_tree = ttk.Treeview(app_canvas, columns=("App Name", "Username", "Password", "Note"), show="headings", height=8)
        self.app_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        app_canvas.configure(yscrollcommand=app_scrollbar.set)
        app_canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.app_tree.heading("App Name", text="App Name")
        self.app_tree.heading("Username", text="Username")
        self.app_tree.heading("Password", text="Password")
        self.app_tree.heading("Note", text="Note")
        
        # Web Passwords Frame
        web_frame = ttk.LabelFrame(main_frame, text="Web Passwords", padding="10")
        web_frame.grid(row=4, column=0, pady=5, padx=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create a frame for the web treeview and scrollbar
        web_tree_frame = ttk.Frame(web_frame)
        web_tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create a canvas and scrollbar for web passwords
        web_canvas = tk.Canvas(web_tree_frame)
        web_scrollbar = ttk.Scrollbar(web_tree_frame, orient="vertical", command=web_canvas.yview)
        web_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.web_tree = ttk.Treeview(web_canvas, columns=("Web URL", "Website Name", "Username", "Password", "Note"), show="headings", height=8)
        self.web_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        web_canvas.configure(yscrollcommand=web_scrollbar.set)
        web_canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.web_tree.heading("Web URL", text="Web URL")
        self.web_tree.heading("Website Name", text="Website Name")
        self.web_tree.heading("Username", text="Username")
        self.web_tree.heading("Password", text="Password")
        self.web_tree.heading("Note", text="Note")
        
        # Configure selection behavior
        self.app_tree.bind('<<TreeviewSelect>>', lambda e: self.on_tree_select('app'))
        self.web_tree.bind('<<TreeviewSelect>>', lambda e: self.on_tree_select('web'))
        
        # Buttons Frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        
        # Delete button with red background and larger size
        delete_button = ttk.Button(
            button_frame, 
            text="🗑️ Delete Selected Password", 
            command=self.delete_selected_password, 
            style='Danger.TButton',
            width=25
        )
        delete_button.grid(row=0, column=0, padx=5, pady=5)
        
        # Back button
        back_button = ttk.Button(button_frame, text="Back to Dashboard", command=self.show_main_dashboard)
        back_button.grid(row=0, column=1, padx=5, pady=5)
        
        # Configure the danger style for the delete button
        style = ttk.Style()
        style.configure('Danger.TButton', 
            foreground='red', 
            font=('Arial', 12, 'bold'),
            padding=10
        )
        
        # Load passwords
        self.load_passwords()

    def perform_search(self):
        """Perform the search operation"""
        search_term = self.search_entry.get().lower().strip()
        
        # Store all items temporarily
        all_app_items = list(self.app_tree.get_children())
        all_web_items = list(self.web_tree.get_children())
        
        # First, reattach all items
        for item in all_app_items:
            self.app_tree.reattach(item, '', 'end')
        for item in all_web_items:
            self.web_tree.reattach(item, '', 'end')
        
        # If search term is empty, show all items
        if not search_term:
            # Update the display
            self.root.update_idletasks()
            return
        
        # Split search term into words for better matching
        search_words = search_term.split()
        
        # Filter app passwords
        for item in all_app_items:
            values = self.app_tree.item(item)['values']
            # Check if any of the search words match any of the values
            if not any(any(word in str(value).lower() for value in values) for word in search_words):
                self.app_tree.detach(item)
        
        # Filter web passwords
        for item in all_web_items:
            values = self.web_tree.item(item)['values']
            # Check if any of the search words match any of the values
            if not any(any(word in str(value).lower() for value in values) for word in search_words):
                self.web_tree.detach(item)
        
        # Update the display
        self.root.update_idletasks()
        
        # Show message if no results found
        if not self.app_tree.get_children() and not self.web_tree.get_children():
            messagebox.showinfo("Search Results", "No matching passwords found")

    def on_tree_select(self, tree_type):
        if tree_type == 'app':
            # Clear web tree selection
            for item in self.web_tree.selection():
                self.web_tree.selection_remove(item)
        else:
            # Clear app tree selection
            for item in self.app_tree.selection():
                self.app_tree.selection_remove(item)

    def delete_selected_password(self):
        # Get selected app password
        selected_app = self.app_tree.selection()
        if selected_app:
            item = selected_app[0]
            password_id = self.app_tree.item(item)['tags'][0]
            values = self.app_tree.item(item)['values']
            
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the password for {values[0]}?"):
                if self.db.delete_app_password(password_id):
                    # Reload the entire page to ensure everything is fresh
                    self.show_delete_password_page()
                    messagebox.showinfo("Success", "Password deleted successfully")
                else:
                    messagebox.showerror("Error", "Failed to delete password")
                return
        
        # Get selected web password
        selected_web = self.web_tree.selection()
        if selected_web:
            item = selected_web[0]
            password_id = self.web_tree.item(item)['tags'][0]
            values = self.web_tree.item(item)['values']
            
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the password for {values[1]}?"):
                if self.db.delete_web_password(password_id):
                    # Reload the entire page to ensure everything is fresh
                    self.show_delete_password_page()
                    messagebox.showinfo("Success", "Password deleted successfully")
                else:
                    messagebox.showerror("Error", "Failed to delete password")
                return
        
        messagebox.showwarning("No Selection", "Please select a password to delete")

    def load_passwords(self):
        # Clear existing items
        for item in self.app_tree.get_children():
            self.app_tree.delete(item)
        for item in self.web_tree.get_children():
            self.web_tree.delete(item)
        
        try:
            # Get current user's passwords
            app_passwords = self.db.get_app_passwords(self.current_user['_id'])
            web_passwords = self.db.get_web_passwords(self.current_user['_id'])
            
            # Add app passwords to treeview
            for password in app_passwords:
                item = self.app_tree.insert('', 'end', values=(
                    password['app_name'],
                    password['username'],
                    password['password'],
                    password.get('note', '')
                ), tags=(str(password['_id']),))
                self.app_tree.see(item)  # Ensure item is visible
            
            # Add web passwords to treeview
            for password in web_passwords:
                item = self.web_tree.insert('', 'end', values=(
                    password['web_url'],
                    password['website_name'],
                    password['username'],
                    password['password'],
                    password.get('note', '')
                ), tags=(str(password['_id']),))
                self.web_tree.see(item)  # Ensure item is visible
            
            # Configure column widths and alignment
            for col in self.app_tree['columns']:
                self.app_tree.column(col, width=150, anchor='w')
                self.app_tree.heading(col, anchor='w')
            
            for col in self.web_tree['columns']:
                self.web_tree.column(col, width=150, anchor='w')
                self.web_tree.heading(col, anchor='w')
            
            # Force update of the display
            self.root.update_idletasks()
            
        except Exception as e:
            print(f"Error loading passwords: {e}")
            messagebox.showerror("Error", "Failed to load passwords")

    def create_account(self):
        username = self.new_username_entry.get()
        email = self.email_entry.get()
        password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not username or not email or not password:
            messagebox.showerror("Error", "All fields are required")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showerror("Error", "Invalid email format")
            return
        
        if self.db.get_user_by_username(username):
            messagebox.showerror("Error", "Username already exists")
            return
        
        if self.db.get_user_by_email(email):
            messagebox.showerror("Error", "Email already exists")
            return
        
        # Generate verification OTP
        otp = generate_otp()
        self.db.create_user(username, email, password)
        self.db.update_user_otp(email, otp)
        
        if send_otp_email(email, otp, is_verification=True):
            messagebox.showinfo("Success", "Account created. Please verify your email.")
            self.show_verify_email_page(email)
        else:
            messagebox.showerror("Error", "Failed to send verification email")

    def show_verify_email_page(self, email):
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        title_label = ttk.Label(main_frame, text="Verify Email", font=('Arial', 20, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=20)
        
        frame = ttk.LabelFrame(main_frame, text="Verification", padding="20")
        frame.grid(row=1, column=0, columnspan=2, pady=10, padx=10)
        
        ttk.Label(frame, text="Enter verification code:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.verify_otp_entry = ttk.Entry(frame, width=30)
        self.verify_otp_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(frame, text="Verify", command=lambda: self.verify_email(email), width=20).grid(row=1, column=0, columnspan=2, pady=10)
        ttk.Button(frame, text="Back to Login", command=self.show_login_page, width=20).grid(row=2, column=0, columnspan=2, pady=5)

    def verify_email(self, email):
        otp = self.verify_otp_entry.get()
        if self.db.verify_user(email, otp):
            messagebox.showinfo("Success", "Email verified successfully")
            self.show_login_page()
        else:
            messagebox.showerror("Error", "Invalid verification code")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        user = self.db.get_user_by_username(username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            self.current_user = user
            self.show_main_dashboard()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def show_main_dashboard(self):
        self.clear_window()
        
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Password Manager", font=('Arial', 20, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # Welcome message
        welcome_label = ttk.Label(main_frame, text=f"Welcome, {self.current_user['username']}!", font=('Arial', 12))
        welcome_label.grid(row=1, column=0, columnspan=2, pady=5)
        
        # Buttons Frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Add App Password button
        add_app_button = ttk.Button(button_frame, text="Add App Password", command=self.show_add_app_password_page, width=20)
        add_app_button.grid(row=0, column=0, padx=5, pady=5)
        
        # Add Web Password button
        add_web_button = ttk.Button(button_frame, text="Add Web Password", command=self.show_add_web_password_page, width=20)
        add_web_button.grid(row=0, column=1, padx=5, pady=5)
        
        # View Passwords button
        view_button = ttk.Button(button_frame, text="View Passwords", command=self.show_view_passwords_page, width=20)
        view_button.grid(row=1, column=0, padx=5, pady=5)
        
        # Delete Passwords button
        delete_button = ttk.Button(button_frame, text="Delete Passwords", command=self.show_delete_password_page, width=20)
        delete_button.grid(row=1, column=1, padx=5, pady=5)
        
        # Profile button
        profile_button = ttk.Button(button_frame, text="Profile", command=self.show_profile_page, width=20)
        profile_button.grid(row=2, column=0, padx=5, pady=5)
        
        # Logout button
        logout_button = ttk.Button(button_frame, text="Logout", command=self.logout, width=20)
        logout_button.grid(row=2, column=1, padx=5, pady=5)

    def show_add_app_password_page(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Add App Password").grid(row=0, column=0, columnspan=2, pady=10)
        
        ttk.Label(frame, text="App Name:").grid(row=1, column=0, sticky=tk.W)
        self.app_name_entry = ttk.Entry(frame)
        self.app_name_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(frame, text="Username:").grid(row=2, column=0, sticky=tk.W)
        self.app_username_entry = ttk.Entry(frame)
        self.app_username_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(frame, text="Password:").grid(row=3, column=0, sticky=tk.W)
        self.app_password_entry = ttk.Entry(frame, show="*")
        self.app_password_entry.grid(row=3, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(frame, text="Note (optional):").grid(row=4, column=0, sticky=tk.W)
        self.app_note_entry = ttk.Entry(frame)
        self.app_note_entry.grid(row=4, column=1, sticky=(tk.W, tk.E))
        
        ttk.Button(frame, text="Save", command=self.save_app_password).grid(row=5, column=0, columnspan=2, pady=10)
        ttk.Button(frame, text="Back to Dashboard", command=self.show_main_dashboard).grid(row=6, column=0, columnspan=2, pady=10)

    def show_add_web_password_page(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Add Web Password").grid(row=0, column=0, columnspan=2, pady=10)
        
        ttk.Label(frame, text="Web URL:").grid(row=1, column=0, sticky=tk.W)
        self.web_url_entry = ttk.Entry(frame)
        self.web_url_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(frame, text="Website Name:").grid(row=2, column=0, sticky=tk.W)
        self.website_name_entry = ttk.Entry(frame)
        self.website_name_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(frame, text="Username:").grid(row=3, column=0, sticky=tk.W)
        self.web_username_entry = ttk.Entry(frame)
        self.web_username_entry.grid(row=3, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(frame, text="Password:").grid(row=4, column=0, sticky=tk.W)
        self.web_password_entry = ttk.Entry(frame, show="*")
        self.web_password_entry.grid(row=4, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(frame, text="Note (optional):").grid(row=5, column=0, sticky=tk.W)
        self.web_note_entry = ttk.Entry(frame)
        self.web_note_entry.grid(row=5, column=1, sticky=(tk.W, tk.E))
        
        ttk.Button(frame, text="Save", command=self.save_web_password).grid(row=6, column=0, columnspan=2, pady=10)
        ttk.Button(frame, text="Back to Dashboard", command=self.show_main_dashboard).grid(row=7, column=0, columnspan=2, pady=10)

    def save_app_password(self):
        app_name = self.app_name_entry.get()
        username = self.app_username_entry.get()
        password = self.app_password_entry.get()
        note = self.app_note_entry.get()
        
        if not app_name or not username or not password:
            messagebox.showerror("Error", "All fields are required")
            return
        
        try:
            # Add the password to the database
            success = self.db.add_app_password(self.current_user['_id'], app_name, username, password, note)
            
            if success:
                # Clear the entry fields
                self.app_name_entry.delete(0, tk.END)
                self.app_username_entry.delete(0, tk.END)
                self.app_password_entry.delete(0, tk.END)
                self.app_note_entry.delete(0, tk.END)
                
                # Show success message
                messagebox.showinfo("Success", "App password saved successfully")
                
                # Return to view passwords page and refresh
                self.show_view_passwords_page()
            else:
                messagebox.showerror("Error", "Failed to save app password to database")
                
        except Exception as e:
            print(f"Error saving app password: {e}")
            messagebox.showerror("Error", "Failed to save app password")

    def save_web_password(self):
        web_url = self.web_url_entry.get()
        website_name = self.website_name_entry.get()
        username = self.web_username_entry.get()
        password = self.web_password_entry.get()
        note = self.web_note_entry.get()
        
        if not web_url or not website_name or not username or not password:
            messagebox.showerror("Error", "Web URL, website name, username, and password are required")
            return
        
        self.db.add_web_password(self.current_user['_id'], web_url, website_name, username, password, note)
        messagebox.showinfo("Success", "Web password saved successfully")
        self.show_main_dashboard()

    def logout(self):
        self.current_user = None
        self.show_login_page()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_forgot_password_page(self):
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        title_label = ttk.Label(main_frame, text="Forgot Password", font=('Arial', 20, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=20)
        
        frame = ttk.LabelFrame(main_frame, text="Password Recovery", padding="20")
        frame.grid(row=1, column=0, columnspan=2, pady=10, padx=10)
        
        ttk.Label(frame, text="Email:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.forgot_email_entry = ttk.Entry(frame, width=30)
        self.forgot_email_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(frame, text="Send OTP", command=self.send_otp, width=20).grid(row=1, column=0, columnspan=2, pady=10)
        ttk.Button(frame, text="Back to Login", command=self.show_login_page, width=20).grid(row=2, column=0, columnspan=2, pady=5)

    def send_otp(self):
        email = self.forgot_email_entry.get()
        user = self.db.get_user_by_email(email)
        
        if not user:
            messagebox.showerror("Error", "Email not found")
            return
        
        otp = generate_otp()
        self.db.update_user_otp(email, otp)
        
        if send_otp_email(email, otp, is_verification=False):
            messagebox.showinfo("Success", "OTP sent to your email")
            self.show_verify_otp_page(email)
        else:
            messagebox.showerror("Error", "Failed to send OTP")

    def show_verify_otp_page(self, email):
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        title_label = ttk.Label(main_frame, text="Verify OTP", font=('Arial', 20, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=20)
        
        frame = ttk.LabelFrame(main_frame, text="Verification", padding="20")
        frame.grid(row=1, column=0, columnspan=2, pady=10, padx=10)
        
        ttk.Label(frame, text="Enter OTP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.otp_entry = ttk.Entry(frame, width=30)
        self.otp_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(frame, text="Verify", command=lambda: self.verify_otp(email), width=20).grid(row=1, column=0, columnspan=2, pady=10)
        ttk.Button(frame, text="Back to Login", command=self.show_login_page, width=20).grid(row=2, column=0, columnspan=2, pady=5)

    def verify_otp(self, email):
        otp = self.otp_entry.get()
        if self.db.verify_user(email, otp):
            messagebox.showinfo("Success", "OTP verified successfully")
            self.show_reset_password_page(email)
        else:
            messagebox.showerror("Error", "Invalid OTP")

    def show_reset_password_page(self, email):
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        title_label = ttk.Label(main_frame, text="Reset Password", font=('Arial', 20, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=20)
        
        frame = ttk.LabelFrame(main_frame, text="New Password", padding="20")
        frame.grid(row=1, column=0, columnspan=2, pady=10, padx=10)
        
        ttk.Label(frame, text="New Password:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.new_password_entry = ttk.Entry(frame, show="*", width=30)
        self.new_password_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(frame, text="Confirm Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.confirm_password_entry = ttk.Entry(frame, show="*", width=30)
        self.confirm_password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(frame, text="Reset Password", command=lambda: self.reset_password(email), width=20).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(frame, text="Back to Login", command=self.show_login_page, width=20).grid(row=3, column=0, columnspan=2, pady=5)

    def reset_password(self, email):
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not new_password or not confirm_password:
            messagebox.showerror("Error", "All fields are required")
            return
        
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        self.db.users.update_one({'email': email}, {'$set': {'password': hashed_password}})
        messagebox.showinfo("Success", "Password reset successfully")
        self.show_login_page()

    def clear_search(self):
        """Clear the search entry and refresh the page"""
        self.search_entry.delete(0, tk.END)
        # Reload the entire view passwords page to ensure everything is fresh
        self.show_view_passwords_page()

    def show_delete_password_page(self):
        self.clear_window()
        
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Back button at the top
        back_button = ttk.Button(main_frame, text="← Back to Dashboard", command=self.show_main_dashboard)
        back_button.grid(row=0, column=0, sticky=tk.W, pady=5)
        
        # Title
        title_label = ttk.Label(main_frame, text="Delete Password", font=('Arial', 24, 'bold'))
        title_label.grid(row=1, column=0, columnspan=2, pady=20)
        
        # Instructions
        instructions = ttk.Label(main_frame, 
                               text="Select a password from the list below and click the Delete button to remove it",
                               font=('Arial', 12))
        instructions.grid(row=2, column=0, columnspan=2, pady=10)
        
        # App Passwords Frame
        app_frame = ttk.LabelFrame(main_frame, text="App Passwords", padding="10")
        app_frame.grid(row=3, column=0, pady=10, padx=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create a frame for the app treeview and scrollbar
        app_tree_frame = ttk.Frame(app_frame)
        app_tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create a canvas and scrollbar for app passwords
        app_canvas = tk.Canvas(app_tree_frame)
        app_scrollbar = ttk.Scrollbar(app_tree_frame, orient="vertical", command=app_canvas.yview)
        app_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.app_tree = ttk.Treeview(app_canvas, columns=("App Name", "Username", "Password", "Note"), show="headings", height=8)
        self.app_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        app_canvas.configure(yscrollcommand=app_scrollbar.set)
        app_canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.app_tree.heading("App Name", text="App Name")
        self.app_tree.heading("Username", text="Username")
        self.app_tree.heading("Password", text="Password")
        self.app_tree.heading("Note", text="Note")
        
        # Web Passwords Frame
        web_frame = ttk.LabelFrame(main_frame, text="Web Passwords", padding="10")
        web_frame.grid(row=4, column=0, pady=10, padx=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create a frame for the web treeview and scrollbar
        web_tree_frame = ttk.Frame(web_frame)
        web_tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create a canvas and scrollbar for web passwords
        web_canvas = tk.Canvas(web_tree_frame)
        web_scrollbar = ttk.Scrollbar(web_tree_frame, orient="vertical", command=web_canvas.yview)
        web_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.web_tree = ttk.Treeview(web_canvas, columns=("Web URL", "Website Name", "Username", "Password", "Note"), show="headings", height=8)
        self.web_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        web_canvas.configure(yscrollcommand=web_scrollbar.set)
        web_canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.web_tree.heading("Web URL", text="Web URL")
        self.web_tree.heading("Website Name", text="Website Name")
        self.web_tree.heading("Username", text="Username")
        self.web_tree.heading("Password", text="Password")
        self.web_tree.heading("Note", text="Note")
        
        # Configure selection behavior
        self.app_tree.bind('<<TreeviewSelect>>', lambda e: self.on_tree_select('app'))
        self.web_tree.bind('<<TreeviewSelect>>', lambda e: self.on_tree_select('web'))
        
        # Buttons Frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        # Delete button with red background and larger size
        delete_button = tk.Button(
            button_frame, 
            text="🗑️ Delete Selected Password", 
            command=self.delete_selected_password,
            bg='#ff4444',  # Red background
            fg='white',    # White text
            font=('Arial', 14, 'bold'),
            width=30,
            height=2,
            relief='raised',
            borderwidth=3,
            cursor='hand2'  # Show hand cursor on hover
        )
        delete_button.grid(row=0, column=0, padx=10, pady=10)
        
        # Back button
        back_button = ttk.Button(button_frame, text="Back to Dashboard", command=self.show_main_dashboard)
        back_button.grid(row=0, column=1, padx=10, pady=10)
        
        # Load passwords
        self.load_passwords()
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Make the window resizable
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def confirm_delete_account(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to delete your account? This action cannot be undone."):
            self.db.users.delete_one({'_id': self.current_user['_id']})
            self.db.app_passwords.delete_many({'user_id': self.current_user['_id']})
            self.db.web_passwords.delete_many({'user_id': self.current_user['_id']})
            messagebox.showinfo("Success", "Account deleted successfully")
            self.logout()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = PasswordManager()
    app.run() 