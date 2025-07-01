import socket, json, base64, os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import hashlib

RECEIVE_FOLDER = 'received'
os.makedirs(RECEIVE_FOLDER, exist_ok=True)

# Load khóa
def load_rsa_key(path):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

server_priv = load_rsa_key('rsa_keys/server_private.pem')
doctor_pub = load_rsa_key('rsa_keys/doctor_public.pem')

# Mật khẩu hợp lệ (SHA-256 của password123)
VALID_PASSWORD_HASH = "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"

# Giải mã AES-CBC
def decrypt_aes(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    pad_len = padded[-1]
    return padded[:-pad_len]

# Kiểm tra chữ ký
def verify_signature(data, signature):
    h = SHA512.new(data)
    try:
        pkcs1_15.new(doctor_pub).verify(h, signature)
        return True
    except:
        return False

# Hàm xử lý gói tin
def handle_packet(packet):
    try:
        iv = base64.b64decode(packet['iv'])
        cipher = base64.b64decode(packet['cipher'])
        sig = base64.b64decode(packet['sig'])
        hashed_pwd = packet['pwd']
        hash_val = packet['hash']
        metadata = packet['metadata'].encode()
        enc_key = base64.b64decode(packet['enc_key'])

        # 1. Kiểm tra mật khẩu
        if hashed_pwd != VALID_PASSWORD_HASH:
            return "NACK: Sai mật khẩu"

        # 2. Kiểm tra chữ ký metadata
        if not verify_signature(metadata, sig):
            return "NACK: Sai chữ ký"

        # 3. Kiểm tra toàn vẹn
        computed_hash = SHA512.new(iv + cipher).hexdigest()
        if computed_hash != hash_val:
            return "NACK: Sai hash toàn vẹn"

        # 4. Giải mã session key
        session_key = PKCS1_OAEP.new(server_priv, hashAlgo=SHA512).decrypt(enc_key)

        # 5. Giải mã file
        data = decrypt_aes(cipher, session_key, iv)

        # 6. Lưu file
        filename = metadata.decode().split('|')[0]
        save_path = os.path.join(RECEIVE_FOLDER, filename)
        with open(save_path, 'wb') as f:
            f.write(data)

        return "ACK: Đã nhận và lưu file thành công"

    except Exception as e:
        return f"NACK: Lỗi xử lý - {str(e)}"

# -----------------------------
# Server TCP socket
HOST = '127.0.0.1'
PORT = 9999

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"[✓] Server đang lắng nghe tại {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        with conn:
            print(f"[+] Kết nối từ {addr}")
            if conn.recv(1024).decode() != "Hello!":
                conn.send(b"NACK: Handshake failed")
                continue
            conn.send(b"Ready!")

            data = conn.recv(1000000).decode()
            try:
                packet = json.loads(data)
                result = handle_packet(packet)
            except Exception as e:
                result = f"NACK: Lỗi JSON - {str(e)}"

            print(f"[=] Phản hồi: {result}")
            conn.send(result.encode())
