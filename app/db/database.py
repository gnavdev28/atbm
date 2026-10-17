import sqlite3
from typing import Tuple, Optional, Dict, Any, List

class DatabaseService:
    """
    Tầng Cơ Sở Dữ Liệu & Kiểm Soát Đồng Thời (Database & Concurrency Layer)
    - Sử dụng SQLite kèm cơ chế WAL (Write-Ahead Logging).
    - Triệt tiêu Race Condition bằng câu lệnh cập nhật nguyên tử (Atomic Conditional Update).
    """

    def __init__(self, db_path: str = "secure_ticketing.db"):
        self.db_path = db_path
        self._mem_conn = None
        if db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", timeout=10.0, check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA busy_timeout = 5000;")

    def get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Bật WAL mode để tăng tốc độ đọc/ghi đồng thời
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    def init_schema(self):
        """Khởi tạo cấu trúc các bảng lưu trữ vé và nhật ký soát vé"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Bảng vé chính
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tickets (
                    id TEXT PRIMARY KEY,
                    owner_name_enc TEXT NOT NULL,
                    tier TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    gate_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    used_at TIMESTAMP
                );
            """)

            # Bảng nhật ký quét vé (Audit log)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS checkin_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id TEXT NOT NULL,
                    gate_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()

    def create_ticket(self, ticket_id: str, owner_name_enc: str, tier: str = "VIP PASS") -> Dict[str, Any]:
        """Tạo mới một vé điện tử vào CSDL"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO tickets (id, owner_name_enc, tier, status)
                VALUES (?, ?, ?, 'ACTIVE');
                """,
                (ticket_id, owner_name_enc, tier)
            )
            conn.commit()
            return {
                "id": ticket_id,
                "owner_name_enc": owner_name_enc,
                "tier": tier,
                "status": "ACTIVE"
            }

    def get_ticket(self, ticket_id: str) -> Optional[Dict[str, Any]]:
        """Lấy thông tin vé theo ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tickets WHERE id = ?;", (ticket_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def reset_ticket(self, ticket_id: str) -> bool:
        """Đặt lại trạng thái vé về ACTIVE để phục vụ demo giảng viên"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE tickets SET status = 'ACTIVE', used_at = NULL, gate_id = NULL WHERE id = ?;", (ticket_id,))
            conn.commit()
            return cursor.rowcount > 0

    def atomic_checkin(self, ticket_id: str, gate_id: str = "GATE-1A") -> Tuple[bool, str]:
        """
        CƠ CHẾ BẢO MẬT CSDL CHƯƠNG 4: ATOMIC CONDITIONAL UPDATE
        Chỉ cập nhật trạng thái khi vé đang ở trạng thái 'ACTIVE'.
        Đảm bảo trong mọi tình huống 20 luồng gửi cùng mili-giây, chỉ có DUY NHẤT 1 luồng
        nhận rowcount == 1, các luồng còn lại nhận rowcount == 0 và bị từ chối ngay.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Câu lệnh nguyên tử kiểm tra điều kiện và cập nhật trong 1 transaction
            cursor.execute(
                """
                UPDATE tickets 
                SET status = 'USED', used_at = CURRENT_TIMESTAMP, gate_id = ? 
                WHERE id = ? AND status = 'ACTIVE';
                """,
                (gate_id, ticket_id)
            )
            
            if cursor.rowcount == 1:
                # Giao dịch thành công
                cursor.execute(
                    "INSERT INTO checkin_logs (ticket_id, gate_id, status, message) VALUES (?, ?, 'SUCCESS', 'Check-in thành công');",
                    (ticket_id, gate_id)
                )
                conn.commit()
                return True, "Check-in thành công. Mời khách vào cửa."
            else:
                # Giao dịch thất bại: Tra cứu lý do
                cursor.execute("SELECT status, used_at FROM tickets WHERE id = ?;", (ticket_id,))
                row = cursor.fetchone()
                
                if not row:
                    msg = "Mã vé không tồn tại trong hệ thống."
                    cursor.execute(
                        "INSERT INTO checkin_logs (ticket_id, gate_id, status, message) VALUES (?, ?, 'REJECTED_NOT_FOUND', ?);",
                        (ticket_id, gate_id, msg)
                    )
                    conn.commit()
                    return False, msg
                
                msg = f"Vé đã được sử dụng trước đó (Lúc: {row['used_at']})."
                cursor.execute(
                    "INSERT INTO checkin_logs (ticket_id, gate_id, status, message) VALUES (?, ?, 'REJECTED_ALREADY_USED', ?);",
                    (ticket_id, gate_id, msg)
                )
                conn.commit()
                return False, msg

    def list_tickets(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Lấy danh sách các vé mới nhất trong CSDL"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tickets ORDER BY created_at DESC LIMIT ?;", (limit,))
            return [dict(r) for r in cursor.fetchall()]

    def list_logs(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Lấy danh sách nhật ký soát vé mới nhất"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM checkin_logs ORDER BY id DESC LIMIT ?;", (limit,))
            return [dict(r) for r in cursor.fetchall()]

