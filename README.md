# VaultMate GUI – Password Manager

A secure, cross-platform, and modern password manager with a user-friendly GUI built using Python, CustomTkinter, and MongoDB. VaultMate ensures your credentials are encrypted and easily accessible, while prioritizing strong security practices like email verification, 2FA, and hashed authentication.


## 🚀 Features

✅ User registration and authentication with email verification

🔐 Secure password storage using encryption

🔍 Password search and filter functionality

🗂️ Organize passwords by categories (App/Web/Custom)

➕ Add, edit, and delete stored passwords

🔄 Password generator built-in

📤 Import/Export support

👤 Profile management (change password, delete account)

🧠 Admin default account (optional)

📧 Gmail integration for verification & password reset

💻 Cross-platform GUI with CustomTkinter



## Setup

1. Clone the repository:
```bash
git clone https://github.com/webtech781/vaultmate-gui.git
cd vaultmate-gui
```
2.Create a Python virtual environment and activate it:

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

macOS/Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory with the following variables:
```
MONGODB_URI=mongodb://localhost:27017/
EMAIL_USER=**********@gmail.com
EMAIL_PASSWORD=**** **** **** ****
```

## Usage

1. Run the application:
   ```bash
   python main.py
   ```
2. Default admin credentials:
   - Username: admin
   - Password: admin123

## Features Guide

### Adding Passwords
- Click "Add App Password" or "Add Web Password"
- Fill in the required details
- Click "Save"

### Viewing Passwords
- Click "View Passwords"
- Use the search box to filter passwords
- Click "Clear" to reset the search

### Deleting Passwords
- Click "Delete Passwords"
- Select a password from the list
- Click the red "Delete Selected Password" button
- Confirm the deletion

### Profile Management
- Click "Profile"
- View your account details
- Change your password
- Delete your account

## Security Features

- Password hashing using bcrypt
- Secure MongoDB connection
- Unique indexes to prevent duplicates
- Input validation
- Confirmation dialogs for important actions 
