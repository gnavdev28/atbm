# BẢNG THUẬT NGỮ & KIẾN TRÚC HỆ THỐNG VÉ ĐIỆN TỬ BẢO MẬT (SECURE QR TICKETING)

Tài liệu này chuẩn hóa toàn bộ thuật ngữ và quyết định thiết kế cho bài tập lớn môn **An Toàn & Bảo Mật Thông Tin**.

---

## 1. Thuật ngữ cốt lõi (Domain Glossary)

- **Dynamic QR Code (Mã QR động):** Mã QR được tái tạo tự động sau mỗi 30 giây trên màn hình người mua. Payload chứa `ticket_id`, `timestamp`, `nonce`, dữ liệu vé được mã hóa và chữ ký số. Hết 30 giây, mã cũ bị vô hiệu hóa để chống chụp ảnh màn hình chia sẻ.
- **AES-256-GCM (Chương 1 & 2 - Bảo mật dữ liệu):** Thuật toán mã hóa đối xứng xác thực (Authenticated Encryption) dùng để mã hóa thông tin người mua (CCCD/Tên/Hạng vé) trong mã QR. Đảm bảo người ngoài không thể đọc trộm thông tin cá nhân.
- **ECDSA P-256 (Chương 3 - Chữ ký số):** Thuật toán chữ ký số trên đường cong Elliptic. Máy chủ dùng Private Key để ký lên mã QR; thiết bị quét cổng dùng Public Key để xác minh tính toàn vẹn và chống giả mạo. Chữ ký ngắn gọn (~64 bytes) giúp mã QR ít hạt và quét siêu nhạy.
- **Atomic Conditional Update (Chương 4 - An ninh CSDL):** Kỹ thuật chống Race Condition / quét trùng do mạng lag. Dùng câu lệnh cập nhật nguyên tử:
  `UPDATE tickets SET status = 'USED', used_at = :now WHERE id = :id AND status = 'ACTIVE'`
  Nếu 2 cổng cùng quét 1 vé cùng lúc, CSDL chỉ cho phép 1 giao dịch thành công (`rows_affected = 1`), giao dịch còn lại nhận `rows_affected = 0` và bị từ chối ngay lập tức.
- **Nonce & Sliding Window (Chương 5 - Chống Replay Attack):** Mỗi mã QR sinh ra một chuỗi ngẫu nhiên (nonce) và timestamp. Server duy trì bộ nhớ tạm (cache) để kiểm tra: nếu mã QR đã quá 30 giây hoặc nonce đã từng được gửi lên trước đó, yêu cầu bị từ chối.
- **Rate Limiter (Chương 5 - Chống DoS / Brute-force):** Giới hạn tần suất gọi API soát vé (ví dụ tối đa 10 request/giây/cổng) để bảo vệ server khi có lượng truy cập đột biến tại giờ cao điểm check-in.
- **Security Lab (Phòng thí nghiệm bảo mật):** Giao diện tương tác trực tiếp giúp giảng viên kiểm chứng thực tế: giả lập sửa mã vé, quét vé quá hạn, nã request đồng thời để chứng minh hệ thống bắt trọn mọi hành vi vi phạm.

---

## 2. Bản đồ cây thiết kế (Design Decisions Matrix)

| Hạng mục | Quyết định đã thống nhất | Mục đích bảo mật |
| :--- | :--- | :--- |
| **Chống chụp màn hình** | Dynamic QR (30s xoay 1 lần) + Khóa trạng thái vé 1 lần | Chặn chia sẻ vé qua mạng xã hội |
| **Bảo mật thông tin vé** | AES-256-GCM (Mã hóa đối xứng) | Bảo vệ quyền riêng tư người mua |
| **Chống làm giả vé** | ECDSA (Curve P-256 / SHA-256) | Xác thực nguồn gốc từ Server (Chữ ký số) |
| **Chống Race Condition** | Atomic Conditional Update (ACID Transaction) | Ngăn 1 vé quét thành công 2 lần do mạng lag |
| **Chống Replay Attack** | Nonce Cache + Timestamp Window (30s) | Ngăn kẻ xấu bắt gói tin để phát lại |
| **Giao diện & Demo** | Clean Industrial Tech (Không mùi AI) + Tab Security Lab | Trực quan, chuyên nghiệp khi bảo vệ bài tập lớn |
