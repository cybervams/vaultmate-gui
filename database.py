import pymongo
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
from dotenv import load_dotenv
import os

load_dotenv()

class Database:
    def __init__(self):
        self.client = MongoClient(os.getenv('MONGODB_URI'))
        self.db = self.client.password_manager
        self.users = self.db.users
        self.app_passwords = self.db.app_passwords
        self.web_passwords = self.db.web_passwords
        
        # Drop existing indexes to handle any duplicates
        try:
            self.app_passwords.drop_indexes()
            self.web_passwords.drop_indexes()
            self.users.drop_indexes()
        except Exception as e:
            print(f"Warning: Could not drop indexes: {e}")
        
        # Create indexes with error handling
        try:
            self.users.create_index('username', unique=True)
            self.users.create_index('email', unique=True)
            
            # For app passwords, first remove any duplicates
            pipeline = [
                {"$group": {
                    "_id": {"user_id": "$user_id", "app_name": "$app_name"},
                    "dups": {"$push": "$_id"},
                    "count": {"$sum": 1}
                }},
                {"$match": {"count": {"$gt": 1}}}
            ]
            duplicates = list(self.app_passwords.aggregate(pipeline))
            
            for dup in duplicates:
                # Keep the first document and delete the rest
                keep_id = dup['dups'][0]
                delete_ids = dup['dups'][1:]
                self.app_passwords.delete_many({"_id": {"$in": delete_ids}})
            
            # Now create the unique index
            self.app_passwords.create_index([('user_id', 1), ('app_name', 1)], unique=True)
            
            # Do the same for web passwords
            pipeline = [
                {"$group": {
                    "_id": {"user_id": "$user_id", "web_url": "$web_url"},
                    "dups": {"$push": "$_id"},
                    "count": {"$sum": 1}
                }},
                {"$match": {"count": {"$gt": 1}}}
            ]
            duplicates = list(self.web_passwords.aggregate(pipeline))
            
            for dup in duplicates:
                # Keep the first document and delete the rest
                keep_id = dup['dups'][0]
                delete_ids = dup['dups'][1:]
                self.web_passwords.delete_many({"_id": {"$in": delete_ids}})
            
            # Now create the unique index
            self.web_passwords.create_index([('user_id', 1), ('web_url', 1)], unique=True)
            
        except Exception as e:
            print(f"Warning: Could not create indexes: {e}")
        
        # Initialize with an admin user if no users exist
        if self.users.count_documents({}) == 0:
            hashed_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
            self.users.insert_one({
                'username': 'admin',
                'email': 'admin@example.com',
                'password': hashed_password,
                'is_admin': True
            })

    def create_user(self, username, email, password):
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'otp': None,
            'verified': False
        }
        return self.users.insert_one(user)

    def get_user_by_username(self, username):
        return self.users.find_one({'username': username})

    def get_user_by_email(self, email):
        return self.users.find_one({'email': email})

    def update_user_otp(self, email, otp):
        return self.users.update_one({'email': email}, {'$set': {'otp': otp}})

    def verify_user(self, email, otp):
        user = self.get_user_by_email(email)
        if user and user['otp'] == otp:
            self.users.update_one({'email': email}, {'$set': {'otp': None, 'verified': True}})
            return True
        return False

    def add_app_password(self, user_id, app_name, username, password, note=None):
        """Add a new app password for a user"""
        try:
            # Convert user_id to ObjectId if it's a string
            if isinstance(user_id, str):
                user_id = ObjectId(user_id)
            
            # Create the password document
            password_doc = {
                'user_id': user_id,
                'app_name': app_name,
                'username': username,
                'password': password,
                'note': note
            }
            
            # Insert the document
            result = self.app_passwords.insert_one(password_doc)
            
            # Verify the insertion
            if result.inserted_id:
                print(f"Successfully added app password with ID: {result.inserted_id}")
                return True
            else:
                print("Failed to add app password: No ID returned")
                return False
                
        except Exception as e:
            print(f"Error adding app password: {e}")
            return False

    def add_web_password(self, user_id, web_url, website_name, username, password, note=None):
        password_data = {
            'user_id': user_id,
            'web_url': web_url,
            'website_name': website_name,
            'username': username,
            'password': password,
            'note': note
        }
        return self.web_passwords.insert_one(password_data)

    def get_app_passwords(self, user_id):
        """Get all app passwords for a user"""
        try:
            # Convert user_id to ObjectId if it's a string
            if isinstance(user_id, str):
                user_id = ObjectId(user_id)
            
            # Find all passwords for the user
            passwords = list(self.app_passwords.find({'user_id': user_id}))
            print(f"Found {len(passwords)} app passwords for user {user_id}")
            return passwords
            
        except Exception as e:
            print(f"Error getting app passwords: {e}")
            return []

    def get_web_passwords(self, user_id):
        return list(self.web_passwords.find({"user_id": str(user_id)}))

    def update_app_password(self, password_id, data):
        return self.app_passwords.update_one(
            {'_id': ObjectId(password_id)},
            {'$set': data}
        )

    def update_web_password(self, password_id, data):
        return self.web_passwords.update_one(
            {'_id': ObjectId(password_id)},
            {'$set': data}
        )

    def delete_app_password(self, password_id):
        """Delete an app password by its ID"""
        try:
            result = self.app_passwords.delete_one({'_id': ObjectId(password_id)})
            return result.deleted_count > 0
        except Exception as e:
            print(f"Error deleting app password: {e}")
            return False

    def delete_web_password(self, password_id):
        """Delete a web password by its ID"""
        try:
            result = self.web_passwords.delete_one({'_id': ObjectId(password_id)})
            return result.deleted_count > 0
        except Exception as e:
            print(f"Error deleting web password: {e}")
            return False

    def delete_user(self, user_id):
        # Delete user's app passwords
        self.app_passwords.delete_many({'user_id': user_id})
        # Delete user's web passwords
        self.web_passwords.delete_many({'user_id': user_id})
        # Delete user account
        return self.users.delete_one({'_id': user_id})

    def login(self, username, password):
        user = self.users.find_one({"username": username})
        if user:
            # Convert the stored password to bytes if it's a string
            stored_password = user['password']
            if isinstance(stored_password, str):
                stored_password = stored_password.encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                return user
        return None 