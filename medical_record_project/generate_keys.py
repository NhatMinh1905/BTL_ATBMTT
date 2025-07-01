from Crypto.PublicKey import RSA
import os

os.makedirs("rsa_keys", exist_ok=True)

# Tạo khóa 2048-bit
def generate_and_save_keypair(name):
    key = RSA.generate(2048)

    private_key = key.export_key()
    with open(f"rsa_keys/{name}_private.pem", "wb") as priv_file:
        priv_file.write(private_key)

    public_key = key.publickey().export_key()
    with open(f"rsa_keys/{name}_public.pem", "wb") as pub_file:
        pub_file.write(public_key)

# Tạo khóa cho bác sĩ và server
generate_and_save_keypair("doctor")
generate_and_save_keypair("server")

print("✅ Đã tạo xong khóa tại thư mục rsa_keys/")
