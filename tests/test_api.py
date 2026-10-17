import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import app_state

client = TestClient(app)

def setup_function():
    # Đặt lại trạng thái vé trước mỗi test
    app_state.db.reset_ticket(app_state.default_ticket_id)

def test_get_dynamic_qr_success():
    """Kiểm tra API cấp phát Dynamic QR xoay vòng 30s kèm chữ ký ECDSA P-256"""
    resp = client.get(f"/api/tickets/{app_state.default_ticket_id}/qr")
    assert resp.status_code == 200
    
    data = resp.json()
    assert "qr_payload" in data
    assert data["expires_in_seconds"] == 30
    
    payload = data["qr_payload"]
    assert payload["tid"] == app_state.default_ticket_id
    assert "sig" in payload
    assert "nonce" in payload
    assert "ts" in payload

def test_full_checkin_flow_success_and_duplicate():
    """Kiểm tra toàn trình quét vé: Lần 1 thành công, Lần 2 bị từ chối ngay lập tức"""
    # 1. Lấy QR động mới nhất từ server
    qr_resp = client.get(f"/api/tickets/{app_state.default_ticket_id}/qr")
    qr_payload = qr_resp.json()["qr_payload"]
    
    # 2. Nhân viên quét mã tại cổng 1A
    checkin_data = {
        "tid": qr_payload["tid"],
        "tier": qr_payload["tier"],
        "ts": qr_payload["ts"],
        "nonce": qr_payload["nonce"],
        "enc": qr_payload["enc"],
        "sig": qr_payload["sig"],
        "gate_id": "GATE-1A",
        "staff_pin": "1234"
    }
    
    # Lần 1: Thành công
    c_resp1 = client.post("/api/checkin", json=checkin_data)
    assert c_resp1.status_code == 200
    res1 = c_resp1.json()
    assert res1["success"] is True
    assert "THÀNH CÔNG" in res1["message"]
    assert res1["owner"]["full_name"] == "Nguyễn Văn An"

    # Lần 2: Quét lại cùng vé đó -> Bị từ chối
    # Đổi nonce mới để không bị vướng lỗi replay nonce trước, nhằm chứng minh CSDL bắt lỗi vé đã dùng
    checkin_data_second = dict(checkin_data)
    checkin_data_second["nonce"] = "new_nonce_distinct"
    # Ký lại cho nonce mới
    core = {
        "tid": checkin_data_second["tid"],
        "tier": checkin_data_second["tier"],
        "ts": checkin_data_second["ts"],
        "nonce": checkin_data_second["nonce"],
        "enc": checkin_data_second["enc"]
    }
    checkin_data_second["sig"] = app_state.crypto.sign_payload(core, app_state.priv_key_pem)

    c_resp2 = client.post("/api/checkin", json=checkin_data_second)
    assert c_resp2.status_code == 200
    res2 = c_resp2.json()
    assert res2["success"] is False
    assert res2["error_code"] == "ALREADY_USED_OR_RACE_CONDITION"

def test_checkin_tampered_fails():
    """Kiểm tra API check-in bắt lỗi làm giả chữ ký số ECDSA"""
    qr_resp = client.get(f"/api/tickets/{app_state.default_ticket_id}/qr")
    qr_payload = qr_resp.json()["qr_payload"]
    
    checkin_data = {
        "tid": qr_payload["tid"],
        "tier": "SUPER_VIP_HACKED", # Sửa trường dữ liệu
        "ts": qr_payload["ts"],
        "nonce": qr_payload["nonce"],
        "enc": qr_payload["enc"],
        "sig": qr_payload["sig"], # Giữ chữ ký cũ không khớp
        "gate_id": "GATE-1A",
        "staff_pin": "1234"
    }
    
    resp = client.post("/api/checkin", json=checkin_data)
    assert resp.status_code == 200
    res = resp.json()
    assert res["success"] is False
    assert res["error_code"] == "FORGERY_DETECTED"

def test_checkin_unauthorized_pin_fails():
    """Kiểm tra mã PIN nhân viên sai bị từ chối 401"""
    qr_resp = client.get(f"/api/tickets/{app_state.default_ticket_id}/qr")
    qr_payload = qr_resp.json()["qr_payload"]
    
    checkin_data = {
        "tid": qr_payload["tid"],
        "tier": qr_payload["tier"],
        "ts": qr_payload["ts"],
        "nonce": qr_payload["nonce"],
        "enc": qr_payload["enc"],
        "sig": qr_payload["sig"],
        "gate_id": "GATE-1A",
        "staff_pin": "9999" # PIN sai
    }
    
    resp = client.post("/api/checkin", json=checkin_data)
    assert resp.status_code == 401

def test_admin_lab_attacks():
    """Kiểm tra các endpoint demo trong Security Lab cho giảng viên"""
    # 1. Test Tamper
    r_tamper = client.post("/api/admin/test-tamper", params={"authorization": "admin123"})
    assert r_tamper.status_code == 200
    assert r_tamper.json()["attack_detected"] is True

    # 2. Test Replay
    r_replay = client.post("/api/admin/test-replay", params={"authorization": "admin123"})
    assert r_replay.status_code == 200
    assert r_replay.json()["attack_detected"] is True

    # 3. Test Concurrency Flood (20 requests)
    r_flood = client.post("/api/admin/test-concurrency", params={"authorization": "admin123"})
    assert r_flood.status_code == 200
    flood_data = r_flood.json()
    assert flood_data["total_requests"] == 20
    assert flood_data["success_admitted"] == 1
    assert flood_data["rejected_blocked"] == 19

def test_reset_ticket_endpoint():
    """Kiểm tra API đặt lại trạng thái vé về ACTIVE"""
    tid = app_state.default_ticket_id
    resp = client.post(f"/api/tickets/{tid}/reset")
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"
    
    t = client.get(f"/api/tickets/{tid}").json()
    assert t["status"] == "ACTIVE"

