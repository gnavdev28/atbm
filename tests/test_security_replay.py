import time
import pytest
from app.services.security_service import SecurityService

def test_fresh_timestamp_and_nonce_valid():
    """Kiểm tra gói tin mới sinh trong 30s với nonce mới được chấp thuận"""
    sec = SecurityService(window_seconds=30)
    now = int(time.time())
    
    valid, msg = sec.validate_timestamp_and_nonce(timestamp=now, nonce="fresh_nonce_1")
    assert valid is True
    assert "hợp lệ" in msg.lower() or "valid" in msg.lower()

def test_expired_timestamp_fails():
    """Kiểm tra gói tin cũ (>30s) bị từ chối chống chụp ảnh màn hình cũ (Replay Attack)"""
    sec = SecurityService(window_seconds=30)
    old_time = int(time.time()) - 35  # Cách đây 35 giây (quá 30s)
    
    valid, msg = sec.validate_timestamp_and_nonce(timestamp=old_time, nonce="nonce_expired")
    assert valid is False
    assert "hết hạn" in msg.lower() or "expired" in msg.lower()

def test_duplicate_nonce_fails():
    """Kiểm tra gửi lại cùng một nonce trong thời hạn hợp lệ bị bắt lỗi Replay Attack"""
    sec = SecurityService(window_seconds=30)
    now = int(time.time())
    nonce = "replay_nonce_99"
    
    # Lần 1: Thành công
    valid1, _ = sec.validate_timestamp_and_nonce(timestamp=now, nonce=nonce)
    assert valid1 is True
    
    # Lần 2: Thất bại vì nonce đã được ghi nhận trước đó
    valid2, msg2 = sec.validate_timestamp_and_nonce(timestamp=now, nonce=nonce)
    assert valid2 is False
    assert "nonce" in msg2.lower() and ("sử dụng" in msg2.lower() or "used" in msg2.lower())

def test_rate_limiter_throttles():
    """Kiểm tra bộ giới hạn tần suất chặn DoS khi gọi dồn dập vượt ngưỡng"""
    sec = SecurityService(rate_limit_per_second=5)
    client_id = "GATE-01"
    
    # Gửi 5 requests liên tiếp: Đều được duyệt
    for _ in range(5):
        allowed = sec.check_rate_limit(client_id)
        assert allowed is True
        
    # Request thứ 6 vượt ngưỡng: Bị chặn lại
    blocked = sec.check_rate_limit(client_id)
    assert blocked is False
