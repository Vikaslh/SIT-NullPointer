# Secure File Storage & User Authentication System

This Flask application provides secure file storage with AES encryption, user authentication, and token-based access control.

## Features

- **User Registration & Login**: Secure authentication with hashed passwords.
- **JWT Authentication**: Token-based authentication for secure access.
- **File Upload & Encryption**: Files are encrypted using AES-256 before storage.
- **Decryption & Download**: Decrypt and download stored files securely.
- **File Management**: Upload, view, and delete encrypted/decrypted files.
- **Dashboard**: View uploaded files in a user-friendly interface.

## Installation

1. **Clone the Repository**  
   ```sh
   git clone https://github.com/Vikaslh/SIT-NullPointer.git
   cd SIT-NullPointer
   ```

2. **Create a Virtual Environment & Install Dependencies**  
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Initialize the Database**  
   ```sh
   python -c "from app import init_db; init_db()"
   ```

4. **Run the Application**  
   ```sh
   python app.py
   ```

5. **Access the Web Interface**  
   Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

## API Endpoints

| Method | Endpoint         | Description                         |
|--------|-----------------|-------------------------------------|
| POST   | `/register`      | Register a new user               |
| POST   | `/login`         | User login & get JWT token        |
| GET    | `/dashboard`     | View uploaded files (Auth required) |
| POST   | `/upload`        | Upload and encrypt a file         |
| GET    | `/download/<filename>` | Download an encrypted file  |
| POST   | `/delete/<file_id>` | Delete a file                  |

## Technologies Used

- **Flask** (Python web framework)
- **SQLite** (Lightweight database)
- **JWT** (Token-based authentication)
- **AES Encryption** (Secure file storage)
- **Bcrypt** (Password hashing)
