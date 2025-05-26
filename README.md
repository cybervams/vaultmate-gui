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


📦 Prerequisites
Python 3.8 or higher

MongoDB instance (local or cloud)

Gmail account with App Password (2FA enabled)

⚙️ Setup Instructions

1.Clone the Repository :
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

4. Create a `.env` file
   In the project root directory, add the following variables:
```
MONGODB_URI=mongodb://localhost:27017/
EMAIL_USER=**********@gmail.com
EMAIL_PASSWORD=**** **** **** ****
```

🔐 Note:
To generate a Gmail App Password:

1). Enable 2-Factor Authentication on your Google account

2). Visit https://myaccount.google.com/apppasswords

3). Generate a password and paste it into EMAIL_PASSWORD

▶️ Running the Application
Start the GUI application:
   ```bash
   python main.py
   ```
If provided, you can use default admin credentials:

Username: ```admin```

Password: ```admin123```

🧭 Usage Guide
🔐 Add New Password
1). Click “Add Password” (Web or App)

2). Enter details (site/app, username, password, category)

3). Click “Save”

📂 Manage Passwords
- View all saved entries

- Use search to filter

- Edit or delete entries with action buttons

- Organize passwords via categories

👤 Profile Management
- Update your password

- View account details

- Delete your account if desired

🧠 Import/Export
- Export stored data for backup

- Import from a supported format

🔒 Security Highlights
- Passwords are encrypted before storage

- Authentication passwords are hashed using ```bcrypt```

- Gmail verification for registration and password reset

- Session and input validation for safe usage

- Unique indexing to prevent duplicate entries

💡 Best Practices
- Never share your master password

- Use strong, unique credentials

- Enable 2FA on all your accounts

- Update passwords regularly

- Keep VaultMate updated for the latest security fixes

🛠️ Support & Contributions
Have a feature request, bug, or question?
👉 Open an issue on GitHub

📄 License
This project is licensed under the MIT License. See the [LICENSE](http://github.com/webtech781/vaultmate-gui?tab=MIT-1-ov-file) file for more information.

