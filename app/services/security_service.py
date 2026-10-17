import time
from typing import Tuple, Dict, List

class SecurityService:
    """
    Tầng An Ninh Mạng (Network Security Layer - Chương 5)
    - Chống Replay Attack: Quản lý cửa sổ trượt (Sliding Window) 30s và bộ đệm NonceCache.
    - Chống DoS / Brute-force: Bộ giới hạn tần suất gọi API (Rate Limiter) dạng Sliding Log.
    """

    def __init__(self, window_seconds: int = 30, nonce_ttl: int = 60, rate_limit_per_second: int = 10):
        self.window_seconds = window_seconds
        self.nonce_ttl = nonce_ttl
        self.rate_limit_per_second = rate_limit_per_second
        
        # Lưu vết {nonce: timestamp_received}
        self._used_nonces: Dict[str, float] = {}
        
        # Lưu vết {client_id: [timestamp_1, timestamp_2, ...]}
        self._rate_limits: Dict[str, List[float]] = {}

    def _prune_nonces(self):
        """Xóa bỏ các nonce cũ quá TTL để tiết kiệm bộ nhớ RAM"""
        now = time.time()
        expired_keys = [k for k, ts in self._used_nonces.items() if now - ts > self.nonce_ttl]
        for k in expired_keys:
            del self._used_nonces[k]

    def validate_timestamp_and_nonce(self, timestamp: int, nonce: str) -> Tuple[bool, str]:
        """
        Xác minh độ tươi (Freshness) và tính đơn nhất (Uniqueness) của mã QR:
        1. Kiểm tra timestamp có nằm trong cửa sổ cho phép (30s) hay không.
        2. Kiểm tra chuỗi ngẫu nhiên Nonce đã từng xuất hiện hay chưa.
        """
        now = time.time()
        age = now - timestamp

        # Chặn mã QR quá hạn 30 giây (chống chụp màn hình gửi đi)
        if age > self.window_seconds:
            return False, f"Mã QR đã hết hạn ({int(age)}s > {self.window_seconds}s). Phát hiện Replay Attack."

        # Chặn timestamp lệch tương lai (chống can thiệp giờ hệ thống)
        if age < -5:
            return False, "Timestamp không hợp lệ (Thời gian tương lai)."

        self._prune_nonces()

        # Chặn Nonce trùng lặp (chống bắt và phát lại gói tin)
        if nonce in self._used_nonces:
            return False, "Nonce đã được sử dụng trước đó. Phát hiện gói tin Replay Attack."

        # Ghi nhận Nonce mới
        self._used_nonces[nonce] = now
        return True, "Cửa sổ thời gian và Nonce hợp lệ."

    def check_rate_limit(self, client_id: str) -> bool:
        """
        Kiểm tra giới hạn tần suất gọi API của cổng quét / IP:
        Chặn DoS hoặc nã request brute-force dồn dập tại thời điểm check-in.
        """
        now = time.time()
        if client_id not in self._rate_limits:
            self._rate_limits[client_id] = []

        # Giữ lại các request trong vòng 1.0 giây vừa qua
        valid_requests = [ts for ts in self._rate_limits[client_id] if now - ts <= 1.0]
        self._rate_limits[client_id] = valid_requests

        if len(valid_requests) < self.rate_limit_per_second:
            self._rate_limits[client_id].append(now)
            return True
        return False
