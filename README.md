# Secure File Storage App

This is a full-stack Flask web application that allows users to securely upload, encrypt, and store files using AES-256 encryption. Files are encrypted at rest and in transit, and can only be decrypted with the correct password.

## Features

* 🔐 AES-256 file encryption using password-derived keys
* 📁 Secure file upload and download
* 🔑 Password-based login with hashed credentials
* 🧑‍💻 User registration and authentication
* 🌐 Responsive Bootstrap UI
* 🗃️ Files stored locally with persistent storage support (suitable for Render)

## Technologies Used

* Python + Flask
* HTML/CSS (Bootstrap)
* Cryptography library (AES via Fernet)
* SQLite (for simple user storage)

## Getting Started

### Local Setup

1. **Clone the repository**:

   ```bash
   git clone https://github.com/yourusername/secure_file_storage.git
   cd secure_file_storage
   ```

2. **Create a virtual environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   ```

3. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the app**:

   ```bash
   flask run
   ```

### Deployment (Render)

1. Push this project to a GitHub repo
2. Create a new Web Service on [Render](https://render.com/)
3. Render will detect the `render.yaml` and auto-configure the service
4. Deploy and get a public URL

## File Structure

```
secure_file_storage/
├── app.py
├── requirements.txt
├── render.yaml
├── templates/
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   └── decrypt_prompt.html
├── static/
├── uploads/
├── utils/
│   └── crypto_utils.py
├── venv/
```

## Security Notes

* All files are encrypted using Fernet symmetric encryption with keys derived from user-supplied passwords.
* Passwords are hashed with PBKDF2 before storage.
* Flask sessions are secured with a `SECRET_KEY`.

## License

MIT License
