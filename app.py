from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import base64

app = Flask(__name__)

# AES Decryption Logic
def decrypt_data(encrypted_data, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)  # Use ECB mode
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
    return decrypted_data.decode('utf-8').strip()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    encryption_key = "my-secret-key-123"  # Replace with the same key used for encryption

    # Decrypt username and password
    try:
        username = decrypt_data(data['username'], encryption_key)
        password = decrypt_data(data['password'], encryption_key)
        print(f"Decrypted Username: {username}")
        print(f"Decrypted Password: {password}")
    except Exception as e:
        return jsonify({'error': 'Decryption failed', 'details': str(e)}), 400

    # Validate login (example)
    if username == "admin" and password == "password123":
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

if __name__ == '__main__':
    app.run(debug=True)
