from flask import Flask, request, render_template, send_from_directory, redirect, url_for, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import uuid
import sqlite3
import jwt
import datetime
import bcrypt
import re
from functools import wraps
from dotenv import load_dotenv

load_dotenv()


key = get_random_bytes(32)  
DB_NAME = 'users.db'
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret_key')
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure maximum upload size (e.g., 16 MB)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB


@app.route('/dashboard', methods=['POST'])
def upload_file():
    if 'data_file' not in request.files:
        return "No file part", 400

    file = request.files['data_file']
    if file.filename == '':
        return "No selected file", 400

    # Save uploaded file to disk
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)

    try:
        # Read the file's content
        with open(file_path, 'rb') as f:
            file_data = f.read()

        # Encrypt the file content using AES (ECB mode)
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

        # Generate a unique ID for this file
        unique_id = str(uuid.uuid4())

        # Save the encrypted data to a new file
        encrypted_filename = f"encrypted_{unique_id}_{file.filename}"
        encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)

        # Decrypt the file automatically after encryption
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        # Save the decrypted file to the server
        decrypted_filename = f"decrypted_{unique_id}_{file.filename}"
        decrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)

        # Store the file's info in the database
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO files (original_filename, encrypted_filename, decrypted_filename) VALUES (?, ?, ?)',(file.filename, encrypted_filename, decrypted_filename))
        conn.commit()
        conn.close()

        return redirect(url_for('dashboard'))

    except Exception as e:
        return f"Error processing the file: {str(e)}", 500

@app.route('/decrypted-files')
def decrypted_files():
    # Fetch all decrypted files from the database
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, original_filename, decrypted_filename FROM files WHERE decrypted_filename IS NOT NULL')
    files = [dict(id=row[0], original_filename=row[1], decrypted_filename=row[2]) for row in cursor.fetchall()]
    conn.close()

    # Render the decrypted files page
    return render_template('view_decrypted_files.html', files=files)

@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    # Fetch file details from the database
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT encrypted_filename, decrypted_filename FROM files WHERE id = ?', (file_id,))
    file = cursor.fetchone()

    if not file:
        conn.close()
        return f"File with ID {file_id} not found.", 404

    encrypted_filename, decrypted_filename = file

    # Delete the files from the server
    try:
        if encrypted_filename:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename))
        if decrypted_filename:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename))
    except FileNotFoundError:
        pass

    # Remove the file record from the database
    cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download_file(filename):
    # Provide the encrypted or decrypted file for download
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        return "File not found.", 404


# ----------------------------------------------------------------


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
    conn.execute('''CREATE TABLE IF NOT EXISTS files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        original_filename TEXT,
                        encrypted_filename TEXT,
                        decrypted_filename TEXT)''')
    conn.commit()
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
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, original_filename, encrypted_filename FROM files')
    files = [dict(id=row[0], original_filename=row[1], encrypted_filename=row[2]) for row in cursor.fetchall()]
    conn.close()

    # Render the upload form and file table
    return render_template('dashboard.html', files=files)

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


