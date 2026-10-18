# ĐẶC TẢ KỸ THUẬT: HỆ THỐNG PHÁT HÀNH VÉ ĐIỆN TỬ QR CHỐNG GIẢ MẠO (SECURE QR TICKETING)

## Problem Statement

Trong các sự kiện thực tế (hội thảo, hòa nhạc, vé xem phim), hệ thống vé điện tử truyền thống dạng mã QR tĩnh gặp phải ba lỗ hổng bảo mật nghiêm trọng:
1. **Chia sẻ lậu bằng ảnh chụp màn hình:** Người mua vé hợp lệ chụp lại mã QR gửi qua mạng xã hội cho nhiều người khác cùng đi ké vào cửa.
2. **Làm giả vé (Ticket Forgery):** Kẻ xấu có thể tự sinh một mã QR chứa định dạng JSON vé sự kiện giả và quét qua mặt các máy đọc thông thường nếu không có chữ ký số mã hóa bảo vệ.
3. **Quét trùng lặp do mạng lag (Race Condition) & Tấn công phát lại (Replay Attack):** Kẻ tấn công bắt gói tin soát vé hợp lệ và nã liên tục đến các cổng quét khác nhau cùng lúc. Nếu hệ thống cơ sở dữ liệu không có cơ chế khóa nguyên tử (Atomic Update), một chiếc vé có thể được check-in thành công 2 lần trước khi trạng thái kịp cập nhật.

## Solution

Xây dựng hệ thống vé điện tử bảo mật toàn diện kết hợp 5 lớp phòng thủ tương ứng giáo trình An toàn bảo mật thông tin:
1. **Dynamic Rotating QR Code:** Mã QR trên máy người dùng tự động sinh lại sau mỗi 30 giây kèm thời gian thực (`timestamp`) và chuỗi ngẫu nhiên (`nonce`). Ảnh chụp màn hình sau 30 giây sẽ bị hệ thống từ chối ngay lập tức.
2. **Ký số ECDSA (Elliptic Curve Cryptography - P-256):** Máy chủ dùng Private Key để ký số lên toàn bộ nội dung vé. Cổng soát vé dùng Public Key để kiểm tra tính toàn vẹn (Integrity) và xác thực nguồn gốc (Authenticity). Bất kỳ sự can thiệp nào vào nội dung vé đều làm chữ ký số sai lệch.
3. **Mã hóa đối xứng AES-256-GCM:** Thông tin định danh cá nhân của khách hàng (Số CCCD, Họ tên) được mã hóa bảo vệ dữ liệu riêng tư (Confidentiality).
4. **Kiểm soát đồng thời nguyên tử (Atomic Conditional Update):** CSDL áp dụng câu lệnh cập nhật có điều kiện `UPDATE tickets SET status = 'USED' WHERE id = :id AND status = 'ACTIVE'`. Đảm bảo trong mọi tình huống tranh chấp dữ liệu chỉ duy nhất 1 giao dịch check-in thành công.
5. **Chống Replay Attack & DoS:** Hệ thống duy trì bộ nhớ tạm (Nonce Cache) trong cửa sổ 30 giây để phát hiện gói tin quét lặp lại, đồng thời tích hợp Rate Limiter chặn các cuộc tấn công nã request dồn dập.
6. **Security Lab:** Giao diện trực quan tích hợp sẵn các kịch bản tấn công thử nghiệm để người dùng và giảng viên trực tiếp kiểm chứng cơ chế phòng thủ.

## User Stories

1. As an attendee, I want to purchase an event ticket with my name, citizen ID (CCCD), and ticket tier, so that I receive an authentic digital ticket pass.
2. As an attendee, I want to view my ticket pass with a dynamic QR code that refreshes every 30 seconds with a countdown progress bar, so that unauthorized screenshot sharing is prevented.
3. As an attendee, I want my personal identity information in the QR payload to be encrypted using AES-256-GCM, so that eavesdroppers scanning my QR code cannot read my private data.
4. As a gatekeeper, I want to use my laptop or mobile browser camera to scan an attendee's QR code at the check-in gate, so that I can instantly verify their ticket.
5. As a gatekeeper, I want the system to verify the ECDSA cryptographic signature of the QR code using the server's public key, so that forged tickets created by bad actors are immediately flagged and rejected with a red warning.
6. As a gatekeeper, I want to see the attendee's decrypted ticket info (name, tier, status) upon successful verification, so that I can grant them entry.
7. As a gatekeeper, I want immediate visual and audio feedback (valid sound / rejection buzzer) when a ticket is scanned, so that high-throughput gate operations are seamless.
8. As a system administrator, I want concurrent check-in attempts on the exact same ticket to be handled with an atomic database conditional update, so that race conditions caused by network lag cannot allow double-entry.
9. As a security engineer, I want repeated submissions of an identical QR payload or expired QR code (> 30s) to be rejected by the nonce and sliding timestamp check, so that network replay attacks are completely mitigated.
10. As a system administrator, I want check-in endpoints to be protected with a rate limiter, so that denial-of-service (DoS) bursts at high-traffic check-in times do not crash the server.
11. As an academic instructor/examiner, I want a dedicated 'Security Lab' dashboard, so that I can deliberately inject tampered payloads, test expired QR screenshots, and trigger 20 simultaneous concurrent requests to verify the security mechanisms firsthand.

## Implementation Decisions

### 1. Phân chia Module & Kiến trúc Phân quyền (RBAC & Separate Portals)
Hệ thống hoạt động như một ứng dụng thực tế (Production-grade), tách biệt hoàn toàn không gian làm việc theo quyền hạn (Role-based Access Control):
- **Cổng Đăng Nhập Tập Trung (`/login` - `login.html`):**
  - Màn hình xác thực tài khoản chuẩn doanh nghiệp.
  - Hỗ trợ 3 tài khoản độc lập có thông tin rõ ràng kèm nút 1-Click Demo để chuyển đổi nhanh:
    1. Khách (`khach` / `khach123`): Cấp quyền truy cập Cổng Khách hàng.
    2. Bảo Vệ (`baove` / `1234`): Cấp quyền mở máy quét an ninh cổng soát vé.
    3. Admin (`admin` / `admin123`): Cấp toàn quyền truy cập Cổng Quản Trị & Lab.
- **Cổng Khách hàng (`/` - `index.html`):** 
  - Khách nhận thẻ vé điện tử cá nhân, xem mã QR động tự xoay vòng sau mỗi 30s kèm thanh đếm ngược.
  - Tối giản, không có các nút can thiệp CSDL trái phép (đã loại bỏ nút reset vé giả lập).
  - Tích hợp bộ đệm cục bộ (`active_ticket_cache`) tính toán thời gian thực tế còn lại từ timestamp mã vé để giữ nguyên vẹn mã QR và tiếp tục đếm ngược khi người dùng chuyển đổi qua lại giữa các tab hoặc các cổng.
  - Thanh Header chỉ hiển thị duy nhất nhãn vai trò `Khách` và nút Đăng xuất.
- **Cổng Soát vé Bảo vệ (`/gatekeeper` - `gatekeeper.html`):** 
  - Giao diện máy quét camera trực tiếp và hỗ trợ tải ảnh vé QR.
  - Tinh giản, loại bỏ hoàn toàn các nút mô phỏng và khung debug audit log lộ liễu.
  - Phản hồi trạng thái tức thời (Xanh / Đỏ) kèm âm thanh beep/buzzer.
  - Báo lỗi chính xác theo từng tình huống an ninh thực tế (Chữ ký giả mạo, Mã QR hết hạn >30s, Replay Attack quét lặp, Vé đã check-in trước đó, Vượt giới hạn Rate Limit).
  - Thanh Header chỉ hiển thị duy nhất nhãn vai trò `Bảo Vệ` và nút Đăng xuất.
- **Phòng Thí nghiệm An ninh & Quản trị (`/admin` - `admin.html`):** 
  - Nơi tập trung toàn bộ công cụ kiểm toán, phân tích mật mã (Cryptographic Inspector), giám sát bản ghi CSDL SQLite thời gian thực và kích hoạt các kịch bản tấn công thử nghiệm (Tamper, Replay, Concurrency Flood).
  - Thanh Header chỉ hiển thị duy nhất nhãn vai trò `Quản Trị / Lab` và nút Đăng xuất.

### 2. Tiêu chuẩn Giao diện (Anti-AI Slop, Dark/Light Mode, Pure i18n)
- **Tuyệt đối loại bỏ phong cách AI Slop:** Không dùng gradient tím neon bóng bẩy, không glow mờ ảo rẻ tiền. Thiết kế phẳng sắc sảo, viền kim loại mảnh 1px, bố cục thực tế theo chuẩn công nghệ doanh nghiệp (Linear Design System).
- **Hỗ trợ Chế độ Sáng / Tối (Dark / Light Theme Toggle):** Tự động nhận diện theme hệ điều hành và cho phép chuyển đổi tức thì, lưu trạng thái vào localStorage.
- **Đa ngôn ngữ chuẩn mực (Pure Tiếng Việt / Pure English):** Có nút chuyển đổi ngôn ngữ độc lập (EN / VI). Hoạt động đồng bộ 100% trên toàn bộ các nhãn thanh điều hướng (Navbar), trạng thái vé thời gian thực (ACTIVE / USED / HỢP LỆ / ĐÃ SỬ DỤNG) và các câu thông báo kiểm tra an ninh mà không cần reload trang.

## Testing Decisions

### Seams kiểm thử
1. **Seam 1 - Core Cryptography Unit Tests:**
   - Test độc lập `crypto_service.py`: Ký chuẩn xác, xác minh đúng; Sửa 1 byte payload -> verify trả về `False`; Mã hóa AES-GCM đúng và giải mã ra đúng dữ liệu gốc.
2. **Seam 2 - Database Concurrency Tests:**
   - Test mô phỏng nhiều luồng (multithreading / asyncio) cùng gọi `atomic_checkin` cho 1 vé duy nhất. Xác nhận chính xác 1 thread thành công và `N - 1` threads bị từ chối.
3. **Seam 3 - Full API Integration Tests (FastAPI TestClient):**
   - Test toàn trình: Tạo vé -> Lấy dynamic QR -> Quét hợp lệ -> Quét lại lần 2 (báo trùng) -> Quét gói tin cũ quá 30s (báo replay).

## Out of Scope

- Tích hợp cổng thanh toán trực tuyến thực tế (VNPAY, Momo). Hệ thống giả lập phát hành vé ngay khi điền thông tin.
- Hệ thống gửi email vé tự động qua SMTP (tập trung toàn bộ vào luồng hiển thị vé điện tử và bảo mật mã QR).
- Phân quyền nhiều cấp độ quản trị viên phức tạp (RBAC đa chi nhánh).

## Further Notes

- Không sử dụng các framework UI nặng nề (Next.js, Vue). Dùng Vanilla HTML5 + Modern CSS (Custom Properties) + Vanilla JS (Web Cryptography / Canvas / HTML5-QRCode scanner) để đảm bảo ứng dụng nhẹ, không phát sinh lỗi môi trường và chạy mượt mà trên mọi máy tính giảng viên.
