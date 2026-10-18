# TÀI LIỆU KIẾN TRÚC HỆ THỐNG: SECURE QR TICKETING

Tài liệu này xác lập mô hình kiến trúc phần mềm, cấu trúc thư mục và các ranh giới thiết kế (Design Seams) cho bài tập lớn môn **An Toàn & Bảo Mật Thông Tin**.

---

## 1. Quyết định Kiến trúc: Layered Architecture (Kiến trúc 3 Lớp)

Thay vì dùng mô hình MVC cổ điển, hệ thống áp dụng **Layered Architecture** hiện đại tối ưu cho FastAPI và Web API:

```
+---------------------------------------------------------------------------------------+
|                                CLIENT TIER (HTML5/JS)                                 |
| login.html (Đăng nhập) | index.html (Khách) | gatekeeper.html (Bảo vệ) | admin.html (Lab)     |
+---------------------------------------------------------------------------------------+
                                     │ (REST JSON via HTTPS)
                                     ▼
+---------------------------------------------------------------------------------------+
|                               PRESENTATION LAYER (FastAPI)                            |
| app/api/auth.py   | app/api/tickets.py   | app/api/checkin.py    | app/api/admin.py   |
+---------------------------------------------------------------------------------------+
                                     │
                                     ▼
+---------------------------------------------------------------------------------------+
|                              SERVICE LAYER (Lõi Nghiệp Vụ)                            |
| crypto_service.py (ECDSA P-256 & AES-GCM)   | security_service.py (Nonce & Rate Limit)|
+---------------------------------------------------------------------------------------+
                                     │
                                     ▼
+---------------------------------------------------------------------------------------+
|                        DATA ACCESS LAYER (SQLite & Atomic Lock)                       |
| db/database.py (Kết nối SQLite, Schema Initialization & Atomic Conditional Update)    |
+---------------------------------------------------------------------------------------+
```

### Tại sao kiến trúc này tối ưu cho môn ATBMTT?
1. **Lõi Mật mã độc lập (`crypto_service.py`):** Hoàn toàn tách biệt khỏi Web framework hay CSDL. Có thể viết Unit Test kiểm thử thuật toán ECDSA và AES-GCM mà không cần khởi động server.
2. **Kiểm soát đồng thời chặt chẽ (`db/database.py`):** Giữ câu lệnh `UPDATE ... WHERE status = 'ACTIVE'` ở tầng dữ liệu, tách biệt với logic HTTP.
3. **Phân quyền vai trò thực tế (RBAC):**
   - Cổng xác thực `/api/auth/login`: Phân quyền 3 cấp độ tài khoản độc lập (`guest`, `guard`, `admin`).
   - Người mua vé: Chỉ tương tác qua endpoint `/api/tickets/...`.
   - Nhân viên soát vé: Phải có Token/PIN xác thực tại cổng `/api/checkin`.
   - Quản trị viên: Có quyền truy cập endpoint kiểm toán và lab tấn công `/api/admin/...`.

---

## 2. Cấu trúc thư mục chi tiết

```
ATBMTT/
├── app/
│   ├── api/                     # Các router FastAPI
│   │   ├── __init__.py
│   │   ├── auth.py              # API xác thực phân quyền 3 vai trò
│   │   ├── tickets.py           # API phát hành & lấy mã QR động (30s)
│   │   ├── checkin.py           # API quét vé & quy trình kiểm soát 5 bước tại cổng
│   │   └── admin.py             # API kiểm toán & phòng thí nghiệm tấn công
│   ├── core/                    # Cấu hình bảo mật hệ thống
│   │   ├── __init__.py
│   │   └── config.py            # Hằng số (cửa sổ 30s, đường cong P-256, nạp key)
│   ├── services/                # Tầng nghiệp vụ cốt lõi
│   │   ├── __init__.py
│   │   ├── crypto_service.py    # Ký số ECDSA & Mã hóa AES-256-GCM
│   │   └── security_service.py  # Bộ đệm Nonce & Giới hạn tần suất (Rate Limiter)
│   ├── db/                      # Tầng truy xuất dữ liệu
│   │   ├── __init__.py
│   │   └── database.py          # Kết nối SQLite, Schema Migration & Atomic Lock Update
│   └── main.py                  # Điểm khởi chạy FastAPI & nạp static web
├── static/                      # Giao diện web người dùng (Linear Design)
│   ├── login.html               # Cổng đăng nhập phân quyền tập trung
│   ├── index.html               # Cổng người mua vé (Dynamic Pass xoay vòng 30s)
│   ├── gatekeeper.html          # Cổng máy quét camera của bảo vệ
│   ├── admin.html               # Cổng quản trị & Security Lab của giảng viên
│   └── linear-theme.css         # Token thiết kế chuẩn Linear (Dark / Light)
├── tests/                       # Bộ kiểm thử tự động TDD (19/19 passing)
│   ├── test_crypto.py           # Kiểm thử toán học mật mã ECDSA / AES
│   ├── test_concurrency.py      # Kiểm thử nã 20 luồng chống Race Condition
│   ├── test_security_replay.py  # Kiểm thử chặn Replay Attack & Nonce
│   └── test_api.py              # Kiểm thử tích hợp toàn trình API
├── requirements.txt             # Danh sách thư viện Python
├── GLOSSARY.md                  # Thuật ngữ môn học
├── SPEC.md                      # Đặc tả kỹ thuật chi tiết
├── DESIGN.md                    # Hướng dẫn thiết kế giao diện Linear
└── ARCHITECTURE.md              # Tài liệu kiến trúc này
```

---

## 3. Bản đồ triển khai (Tracer-bullet Tickets Roadmap)

- **Ticket 01:** Lõi Mật mã (`crypto_service.py` + `test_crypto.py`).
- **Ticket 02:** Cơ sở dữ liệu SQLite & Xử lý tranh chấp đồng thời (`db/database.py` + `test_concurrency.py`).
- **Ticket 03:** Dynamic QR Xoay 30s & Chống Replay Attack (`security_service.py` + `test_security_replay.py`).
- **Ticket 04:** Kết nối API với Giao diện Khách (`index.html`) & Máy quét (`gatekeeper.html`).
- **Ticket 05:** Kết nối API Phòng Thí Nghiệm Tấn Công (`admin.html`), Cổng Đăng Nhập Phân Quyền (`login.html`) & Hoàn thiện kịch bản bảo vệ bài tập lớn.
