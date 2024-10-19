# CS6303-FinalProject-SonikaSowdari
#File: mainapp.py
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dbmodels import db, User, Profile, Message
from encrypt import encrypt_message, decrypt_message
from mfa import generate_mfa_code, verify_mfa_code

app = Flask(__name__)
app.config.from_object('config.Config')
    
# Initializing extensions
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Creating tables
@app.before_first_request
def create_tables():
    db.create_all()
    
# For user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message="User registered successfully"), 201
    
# For user login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        # Generate MFA code and return it
        mfa_code = generate_mfa_code()
        return jsonify(mfa_code=mfa_code, message="MFA code sent"), 200
    else:
        return jsonify(message="Login failed"), 401

# Multi-Factor Authentication Verification
@app.route('/verify_mfa', methods=['POST'])
def verify_mfa():
    data = request.get_json()
    if verify_mfa_code(data['mfa_code']):
        access_token = create_access_token(identity={'username': data['username']})
        return jsonify(access_token=access_token), 200
    else:
        return jsonify(message="MFA verification failed"), 401
    
# JWT protected Profile Creation
@app.route('/profile', methods=['POST'])
@jwt_required()
def create_profile():
    current_user = get_jwt_identity()
    data = request.get_json()
    user = User.query.filter_by(username=current_user['username']).first()
    new_profile = Profile(full_name=data['full_name'], bio=data.get('bio'), owner=user)
    db.session.add(new_profile)
    db.session.commit()
    return jsonify(message="Profile created"), 201

# Encrypted messaging  
@app.route('/message/<int:id>', methods=['GET'])
@jwt_required()
def get_message(id):
    message = Message.query.get(id)
    decrypted_content = decrypt_message(message.content)
    return jsonify(message=decrypted_content), 200

if __name__ == '__main__':
    app.run(debug=True)

#File: dbmodels.py (Database models)
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    profile = db.relationship('Profile', backref='owner', uselist=False)

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, nullable=False)
    recipient_id = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=False)

#File: config.py (Configuration settings) 
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'supersecretkey'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwtsecretkey'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///e_matchmaker.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

#File: mfa.py (Multi-Factor Authentication)
import pyotp

def generate_mfa_code():
    totp = pyotp.TOTP(pyotp.random_base32())
    return totp.now()

def verify_mfa_code(code):
    totp = pyotp.TOTP(pyotp.random_base32())
    return totp.verify(code)

#File: encrypt.py (Encryption)
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt_message(message):
    return cipher_suite.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message.encode()).decode()

#File: req.txt (Required texts)
Flask==3.0.3
Flask-SQLAlchemy==3.1.1
Flask-Bcrypt==1.0.1
Flask-JWT-Extended==4.6.0
cryptography==43.0.1
pyotp==2.6.0
