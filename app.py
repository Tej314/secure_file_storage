from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os, sqlite3, io
from utils.crypto_utils import generate_key, encrypt_file, decrypt_file

app = Flask(__name__)
app.secret_key = os.urandom(24)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def get_db():
    conn = sqlite3.connect('users.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    return conn

@app.route('/')
def index():
    if 'username' in session:
        files = os.listdir(app.config['UPLOAD_FOLDER'])
        return render_template('dashboard.html', files=files)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            db.commit()
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user[2], password):
            session['username'] = username
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))
    file = request.files['file']
    password = request.form['password']
    if file and password:
        salt = os.urandom(16)
        key = generate_key(password, salt)
        encrypted_data = encrypt_file(file.read(), key)
        filename = secure_filename(file.filename)
        with open(os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc'), 'wb') as f:
            f.write(salt + encrypted_data)
        flash('File uploaded and encrypted successfully.')
    return redirect(url_for('index'))

@app.route('/download/<filename>', methods=['GET', 'POST'])
def download(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        password = request.form['password']
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(path, 'rb') as f:
            data = f.read()
        salt, encrypted_data = data[:16], data[16:]
        key = generate_key(password, salt)
        try:
            decrypted_data = decrypt_file(encrypted_data, key)
            return send_file(io.BytesIO(decrypted_data), as_attachment=True, download_name=filename.replace('.enc', ''))
        except Exception:
            flash('Decryption failed. Wrong password?')
    return render_template('decrypt_prompt.html', filename=filename)

if __name__ == '__main__':
    app.run(debug=True)
