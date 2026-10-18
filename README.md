# SecurePass: Hệ Thống Vé Điện Tử QR Chống Giả Mạo & Kiểm Soát An Ninh

> **Đồ án môn học:** An Toàn & Bảo Mật Thông Tin (ATBMTT)  
> **Kiến trúc:** Layered Architecture (FastAPI + SQLite WAL + Modern Vanilla Web)

---

## 📌 Giới thiệu & Bài toán thực tế

Trong các sự kiện thực tế, hệ thống vé điện tử mã QR tĩnh truyền thống đối mặt với 3 nguy cơ an ninh nghiêm trọng:
1. **Chia sẻ lậu ảnh chụp màn hình:** Khách mua vé hợp lệ chụp lại màn hình gửi cho nhiều người đi ké.
2. **Làm giả vé (Ticket Forgery):** Kẻ xấu tự tạo mã QR chứa thông tin vé giả để qua mặt máy quét thông thường.
3. **Quét trùng do nghẽn mạng (Race Condition) & Tấn công phát lại (Replay Attack):** Kẻ gian bắt gói tin soát vé hợp lệ và nã liên tục vào nhiều cổng soát cùng lúc.

**SecurePass** giải quyết triệt để các vấn đề trên bằng 5 lớp phòng thủ tương ứng giáo trình An toàn bảo mật thông tin.

---

## 🛡️ 5 Lớp Phòng Thủ Bảo Mật Cốt Lõi

| STT | Cơ chế bảo mật | Công nghệ & Thuật toán | Mục tiêu an ninh |
| :---: | :--- | :--- | :--- |
| **1** | **Dynamic Rotating QR** | Timestamp trượt + Nonce xoay vòng mỗi 30s | Chống chụp màn hình chia sẻ lậu |
| **2** | **Chữ ký số bất đối xứng** | **ECDSA (NIST P-256 / SHA-256)** | Chống làm giả vé (Integrity & Authenticity) |
| **3** | **Mã hóa dữ liệu cá nhân** | **AES-256-GCM** (Khóa đối xứng) | Bảo vệ bí mật thông tin cá nhân (Confidentiality) |
| **4** | **Kiểm soát đồng thời nguyên tử** | **SQLite Atomic Conditional Update** | Chống Race Condition vé bị check-in 2 lần |
| **5** | **Chống Replay & DoS** | Nonce Cache 30s + Sliding Window Rate Limiter | Chặn bắt lại gói tin và tấn công nã request |

---

## 🏛️ Kiến Trúc Phân Quyền (3 Cổng Riêng Biệt)

Hệ thống hoạt động với cổng đăng nhập tập trung (`/login`) tích hợp phân quyền vai trò (Role-based Access Control):

- **Cổng Khách Hàng (`/`):** Nhận thẻ vé điện tử, hiển thị mã QR động xoay vòng mỗi 30 giây kèm thanh đếm ngược thời gian thực (duy trì trạng thái qua `active_ticket_cache` khi chuyển đổi tab).
- **Cổng Soát Vé Bảo Vệ (`/gatekeeper`):** Quét mã QR trực tiếp qua Camera Webcam hoặc tải ảnh vé, xác minh chữ ký số ECDSA thời gian thực, phát cảnh báo âm thanh và phân loại lỗi an ninh chi tiết.
- **Phòng Lab Quản Trị (`/admin`):** Công cụ phân tích mật mã (Cryptographic Inspector), kiểm toán nhật ký thời gian thực và kích hoạt các kịch bản tấn công thử nghiệm (Tạo vé giả, Phát lại vé hết hạn, Nã 20 luồng đồng thời).

---

## 🚀 Hướng Dẫn Cài Đặt & Khởi Chạy

### 1. Yêu cầu môi trường
- Python 3.10 trở lên
- Trình duyệt hiện đại (Chrome, Edge, Firefox)

### 2. Cài đặt thư viện
```bash
# Tạo môi trường ảo
python -m venv venv

# Kích hoạt môi trường ảo (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# Cài đặt thư viện phụ thuộc
pip install -r requirements.txt
```

### 3. Khởi chạy máy chủ
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Truy cập hệ thống tại: **`http://127.0.0.1:8000/login`**

### 4. Tài khoản Demo kiểm thử nhanh
| Vai trò | Tên đăng nhập | Mật khẩu / PIN | Cổng truy cập |
| :--- | :--- | :--- | :--- |
| **Khách Hàng** | `khach` | `khach123` | `http://127.0.0.1:8000/` |
| **Bảo Vệ** | `baove` | `1234` | `http://127.0.0.1:8000/gatekeeper` |
| **Quản Trị Viên** | `admin` | `admin123` | `http://127.0.0.1:8000/admin` |

*(Tại trang `/login` có sẵn các nút 1-Click Demo để chuyển vai trò tức thì mà không cần gõ phím).*

---

## 🧪 Kiểm Thử Tự Động (TDD)

Dự án đi kèm bộ kiểm thử tự động toàn diện với 19 test cases bao phủ toàn bộ lõi mật mã, kiểm soát đồng thời và tích hợp API:

```bash
pytest -v
```

Kết quả: **19/19 test cases Passed (100%)**.

---

## 📚 Tài Liệu Kỹ Thuật Chi Tiết

- [Đặc tả kỹ thuật (SPEC.md)](docs/SPEC.md)
- [Kiến trúc hệ thống (ARCHITECTURE.md)](docs/ARCHITECTURE.md)
- [Quy chuẩn thiết kế Linear UI (DESIGN.md)](docs/DESIGN.md)
- [Bảng thuật ngữ an toàn thông tin (GLOSSARY.md)](docs/GLOSSARY.md)
