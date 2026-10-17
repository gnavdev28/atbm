import threading
import pytest
from app.db.database import DatabaseService

def test_single_checkin_success():
    """Kiểm tra check-in vé hợp lệ lần đầu thành công"""
    db = DatabaseService(db_path=":memory:")
    db.init_schema()
    
    ticket_id = "TK-TEST-001"
    db.create_ticket(ticket_id=ticket_id, owner_name_enc="ENC_AN", tier="VIP PASS")
    
    success, msg = db.atomic_checkin(ticket_id, gate_id="GATE-1A")
    assert success is True
    assert "thành công" in msg.lower() or "granted" in msg.lower()

def test_second_checkin_fails():
    """Kiểm tra quét lại vé đã sử dụng bị từ chối ngay lập tức"""
    db = DatabaseService(db_path=":memory:")
    db.init_schema()
    
    ticket_id = "TK-TEST-002"
    db.create_ticket(ticket_id=ticket_id, owner_name_enc="ENC_AN", tier="VIP PASS")
    
    # Lần 1: Thành công
    success1, _ = db.atomic_checkin(ticket_id, gate_id="GATE-1A")
    assert success1 is True
    
    # Lần 2: Thất bại vì trạng thái đã là USED
    success2, msg2 = db.atomic_checkin(ticket_id, gate_id="GATE-1B")
    assert success2 is False
    assert "đã được sử dụng" in msg2.lower() or "already" in msg2.lower()

def test_20_concurrent_threads_race_condition(tmp_path):
    """
    KIỂM THỬ TRANH CHẤP ĐỒNG THỜI (RACE CONDITION) - CHƯƠNG 4:
    Mô phỏng 20 threads nã lệnh check-in cùng 1 mili-giây cho 1 vé duy nhất.
    Đảm bảo: Đúng 1 thread thành công, 19 threads thất bại.
    """
    db_file = str(tmp_path / "test_concurrency.db")
    db = DatabaseService(db_path=db_file)
    db.init_schema()
    
    target_ticket = "TK-CONCURRENT-999"
    db.create_ticket(ticket_id=target_ticket, owner_name_enc="ENC_CONCURRENT", tier="VIP PASS")
    
    results = []
    threads = []
    
    def worker(worker_id):
        worker_db = DatabaseService(db_path=db_file)
        success, msg = worker_db.atomic_checkin(target_ticket, gate_id=f"GATE-{worker_id}")
        results.append((worker_id, success, msg))

    # Khởi chạy 20 threads song song
    for i in range(1, 21):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
    
    for t in threads:
        t.start()
    for t in threads:
        t.join()
        
    assert len(results) == 20
    
    success_count = sum(1 for _, s, _ in results if s is True)
    failed_count = sum(1 for _, s, _ in results if s is False)
    
    assert success_count == 1, f"Kỳ vọng đúng 1 vé thành công, thực tế có {success_count} vé lọt qua!"
    assert failed_count == 19, f"Kỳ vọng 19 vé bị chặn, thực tế có {failed_count} vé bị chặn!"
