# vaultmate-gui(Password Manager)

A secure, cross-platform GUI-based password manager built with Python and MongoDB. Store, manage, and retrieve your passwords safely with encryption and a simple user interface.

## Features

- User authentication (login/register)
- Secure password storage
- App and web password management
- Password search functionality
- Password deletion
- User profile management
- Change password option

## Installation

1. Clone the repository

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

3. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```
4. Create a `.env` file with your MongoDB connection string:
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
