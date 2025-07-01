from flask import Flask, render_template, request, redirect, session, send_from_directory, flash
import os
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'received'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

VALID_USERS = {
    "admin": "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"  # SHA-256 của 'password123'
}

def verify_password(username, password):
    if username in VALID_USERS:
        hashed = hashlib.sha256(password.encode()).hexdigest()
        print(f">>> Nhập: {password}")
        print(f">>> Hash nhập: {hashed}")
        print(f">>> Hash đúng: {VALID_USERS[username]}")
        return hashed == VALID_USERS[username]
    return False


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        if verify_password(user, pwd):
            session['user'] = user
            return redirect('/dashboard')
        else:
            flash("Sai tài khoản hoặc mật khẩu", "error")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    files = os.listdir(UPLOAD_FOLDER)
    return render_template('dashboard.html', files=files)

@app.route('/download/<filename>')
def download(filename):
    if 'user' not in session:
        return redirect('/')
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, port=5001)
