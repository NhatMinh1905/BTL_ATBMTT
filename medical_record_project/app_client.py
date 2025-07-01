from flask import Flask, render_template, request, redirect, flash
import socket, base64, json, time, os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
import hashlib

app = Flask(__name__)
app.secret_key = 'secret'
UPLOAD_FOLDER = 'uploads/'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def load_rsa_key(path):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

def encrypt_aes(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_len = 16 - len(data) % 16
    data += bytes([pad_len]) * pad_len
    return cipher.encrypt(data)

def sha512_hash(data):
    return SHA512.new(data).hexdigest()

def sign_data(data, priv_key):
    h = SHA512.new(data)
    return pkcs1_15.new(priv_key).sign(h)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        password = request.form['password']

        if not uploaded_file or not password:
            flash("Vui lòng nhập đủ thông tin", "error")
            return redirect('/')

        file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(file_path)

        with open(file_path, 'rb') as f:
            file_data = f.read()

        doctor_priv = load_rsa_key('rsa_keys/doctor_private.pem')
        server_pub = load_rsa_key('rsa_keys/server_public.pem')

        timestamp = str(int(time.time()))
        metadata = f"{uploaded_file.filename}|{timestamp}|ID1234".encode()
        signature = sign_data(metadata, doctor_priv)
        hashed_pwd = hashlib.sha256(password.encode()).hexdigest()

        session_key = get_random_bytes(32)
        iv = get_random_bytes(16)
        cipher = encrypt_aes(file_data, session_key, iv)

        hash_val = sha512_hash(iv + cipher)
        enc_session_key = PKCS1_OAEP.new(server_pub, hashAlgo=SHA512).encrypt(session_key)

        packet = {
            "iv": base64.b64encode(iv).decode(),
            "cipher": base64.b64encode(cipher).decode(),
            "hash": hash_val,
            "sig": base64.b64encode(signature).decode(),
            "pwd": hashed_pwd,
            "metadata": metadata.decode(),
            "enc_key": base64.b64encode(enc_session_key).decode()
        }

        try:
            s = socket.socket()
            s.connect(('localhost', 9999))
            s.send(b'Hello!')
            if s.recv(1024).decode() != 'Ready!':
                flash("Server không phản hồi", "error")
                return redirect('/')
            s.send(json.dumps(packet).encode())
            response = s.recv(1024).decode()
            flash(f"Phản hồi từ server: {response}", "success" if "ACK" in response else "error")
            s.close()
        except Exception as e:
            flash(f"Lỗi gửi file: {str(e)}", "error")

        return redirect('/')

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
