import os
from flask import Flask, render_template, request, jsonify
import sqlite3
import jwt
import datetime
import bcrypt
import re
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret_key')

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT,
            last_name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.close()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        id = request.headers.get('id')
        conn = get_db_connection()
        jwt_token = conn.execute('SELECT jwt FROM users WHERE id = ?',(id,))
        jwt_token = jwt_token.fetchone()
        if jwt_token:
            print(jwt_token['jwt'])
            if jwt_token == token:
                conn.close()
                
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not all(data.get(field) for field in ['first_name', 'last_name', 'email', 'password']):
        return jsonify({"message": "All fields are required"}), 400

    if not re.match(r"[^@]+@[^@]+\.[^@]+", data['email']):
        return jsonify({"message": "Invalid email format"}), 400

    if len(data['password']) < 8:
        return jsonify({"message": "Password must be at least 8 characters"}), 400

    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO users (first_name, last_name, email, password)
            VALUES (?, ?, ?, ?)
        ''', (data['first_name'], data['last_name'], data['email'], hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"message": "Email already registered"}), 400
    finally:
        conn.close()

    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400


    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        payload = {
            'user_id': user['id'],
            'email': user['email'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

        conn.execute('''UPDATE users SET jwt = ? WHERE email = ?''',(token, user['email'],))
        conn.commit()
        conn.close()
        return jsonify({
            'token': token,
            'user': {
                'id': user['id'],
                'name': f"{user['first_name']} {user['last_name']}"
            }
        }), 200
    conn.close()

    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/logout', methods=['GET'])
# @token_required
def logout():
    return jsonify({'message': 'Logged out successfully'}), 200

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
