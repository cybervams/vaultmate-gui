import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os

load_dotenv()

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(email, otp, is_verification=False):
    sender_email = os.getenv('EMAIL_USER')
    sender_password = os.getenv('EMAIL_PASSWORD')
    
    # Create message container
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    
    if is_verification:
        msg['Subject'] = 'Email Verification - Password Manager'
        body = f"""
        Thank you for creating an account with Password Manager!
        
        Your verification code is: {otp}
        
        Please enter this code to verify your email address.
        
        If you did not create an account, please ignore this email.
        """
    else:
        msg['Subject'] = 'Password Reset - Password Manager'
        body = f"""
        You have requested to reset your password.
        
        Your password reset code is: {otp}
        
        Please enter this code to reset your password.
        
        If you did not request this, please ignore this email.
        """
    
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False 