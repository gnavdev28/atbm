import threading
import time
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel

from app.core.config import app_state

router = APIRouter(prefix="/api/admin", tags=["Security Lab & Admin"])

def verify_admin_auth(auth_token: str):
    if auth_token != "admin123":
        raise HTTPException(status_code=401, detail="Yêu cầu quyền Quản trị viên (admin123)")

@router.get("/keys")
def get_system_keys(authorization: str = "admin123"):
    """Lấy thông tin cặp khóa công khai và trạng thái bảo mật của hệ thống"""
    verify_admin_auth(authorization)
    return {
        "ecdsa_curve": "NIST P-256 (SECP256R1)",
        "hash_algorithm": "SHA-256",
        "symmetric_cipher": "AES-256-GCM (256-bit key, 96-bit nonce, 128-bit MAC tag)",
        "public_key_pem": app_state.pub_key_pem.decode('utf-8'),
        "window_seconds": app_state.security.window_seconds,
        "default_ticket_id": app_state.default_ticket_id
    }

@router.post("/reset-ticket")
def reset_demo_ticket(authorization: str = "admin123"):
    """Đặt lại trạng thái vé demo về ACTIVE để phục vụ trình diễn nhiều lần"""
    verify_admin_auth(authorization)
    app_state.db.reset_ticket(app_state.default_ticket_id)
    return {"status": "success", "message": f"Đã đặt lại trạng thái vé {app_state.default_ticket_id} về ACTIVE"}

@router.post("/test-tamper")
def test_tamper_attack(authorization: str = "admin123"):
    """
    KỊCH BẢN TẤN CÔNG 1: LÀM GIẢ NỘI DUNG VÉ (CHƯƠNG 3 - CHỮ KÝ SỐ)
    Kẻ tấn công sửa đổi trường 'tier' từ 'STANDARD' thành 'SUPER_VIP' mà không có Private Key máy chủ.
    """
    verify_admin_auth(authorization)
    
    # 1. Server ký vé Standard gốc
    original_payload = {
        "tid": "TK-ATTACK-001",
        "tier": "STANDARD",
        "ts": int(time.time()),
        "nonce": "tamper_test_nonce",
        "enc": "AES_ENC_DUMMY"
    }
    valid_sig = app_state.crypto.sign_payload(original_payload, app_state.priv_key_pem)

    # 2. Kẻ tấn công sửa nội dung vé nhưng giữ nguyên chữ ký cũ
    tampered_payload = dict(original_payload)
    tampered_payload["tier"] = "SUPER_VIP_HACKED"

    # 3. Xác minh chữ ký số
    is_valid = app_state.crypto.verify_signature(tampered_payload, valid_sig, app_state.pub_key_pem)

    return {
        "attack_name": "Tamper Payload Forgery",
        "attack_detected": not is_valid,
        "modified_field": "tier: 'STANDARD' -> 'SUPER_VIP_HACKED'",
        "ecdsa_verification_result": is_valid,
        "explanation": "Do hàm băm SHA-256 của nội dung bị thay đổi, chữ ký số ECDSA không khớp với Public Key máy chủ. Tấn công bị chặn đứng hoàn toàn."
    }

@router.post("/test-replay")
def test_replay_attack(authorization: str = "admin123"):
    """
    KỊCH BẢN TẤN CÔNG 2: TẤN CÔNG PHÁT LẠI (CHƯƠNG 5 - AN NINH MẠNG)
    Gửi lại mã QR cũ chụp từ 5 phút trước (hoặc gửi lại Nonce cũ đã dùng).
    """
    verify_admin_auth(authorization)
    
    old_timestamp = int(time.time()) - 300  # Cách đây 5 phút (quá 30 giây)
    nonce = "replay_attack_nonce"
    
    is_valid, reason = app_state.security.validate_timestamp_and_nonce(old_timestamp, nonce)

    return {
        "attack_name": "Replay Expired Screenshot",
        "attack_detected": not is_valid,
        "timestamp_age_seconds": 300,
        "allowed_threshold_seconds": 30,
        "server_response": reason,
        "explanation": "Hệ thống kiểm tra cửa sổ trượt (30s) và bộ đệm NonceCache. Ảnh chụp màn hình cũ bị phát hiện và từ chối ngay lập tức."
    }

@router.post("/test-concurrency")
def test_concurrency_attack(authorization: str = "admin123"):
    """
    KỊCH BẢN TẤN CÔNG 3: TRANH CHẤP ĐỒNG THỜI (CHƯƠNG 4 - AN TOÀN CSDL)
    Giả lập 20 cổng quét nã request check-in cùng 1 mili-giây cho 1 vé hợp lệ.
    """
    verify_admin_auth(authorization)
    
    concurrency_ticket_id = f"TK-FLOOD-{int(time.time())}"
    app_state.db.create_ticket(concurrency_ticket_id, "ENC_NAME_FLOOD", "VIP PASS")

    results = []
    threads = []

    def worker(worker_id):
        success, msg = app_state.db.atomic_checkin(concurrency_ticket_id, gate_id=f"GATE-{worker_id}")
        results.append({
            "worker_id": worker_id,
            "success": success,
            "message": msg
        })

    for i in range(1, 21):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    success_count = sum(1 for r in results if r["success"] is True)
    failed_count = sum(1 for r in results if r["success"] is False)

    return {
        "attack_name": "Concurrency Flood (20 Parallel Gates)",
        "total_requests": 20,
        "success_admitted": success_count,
        "rejected_blocked": failed_count,
        "results_details": sorted(results, key=lambda x: x["worker_id"]),
        "explanation": "Câu lệnh UPDATE nguyên tử trong ACID transaction đảm bảo chỉ duy nhất 1 luồng nhận rowcount == 1, 19 luồng còn lại bị từ chối. Triệt tiêu hoàn toàn Race Condition."
    }
