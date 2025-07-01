# 🔐 Gửi Bệnh Án Với Xác Thực Kép

Hệ thống mô phỏng quy trình gửi bệnh án nhạy cảm từ bác sĩ đến phòng lưu trữ hồ sơ y tế trong bệnh viện, đảm bảo **bảo mật**, **xác thực**, và **toàn vẹn dữ liệu** bằng nhiều lớp bảo vệ:

- AES-CBC để mã hóa bệnh án
- RSA-OAEP 2048-bit để trao đổi khóa và xác minh danh tính
- SHA-512 để kiểm tra toàn vẹn
- SHA-256 để xác thực mật khẩu

---

## 🧩 Thành phần hệ thống

| Thành phần        | Mô tả |
|------------------|------|
| `app_client.py`  | Giao diện Flask để bác sĩ upload bệnh án |
| `app_server.py`  | Giao diện Flask để phòng lưu trữ quản lý & tải file |
| `server_socket.py` | Socket Server xử lý xác thực & nhận file |
| `rsa_keys/`      | Chứa khóa RSA (private & public) của client và server |
| `uploads/`       | File tạm do client upload |
| `received/`      | File được giải mã và lưu trữ tại server |
| `templates/`     | Giao diện HTML đẹp với Bootstrap |
