from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Optional, Dict, Any

from app.core.config import app_state

router = APIRouter(prefix="/api/checkin", tags=["Gatekeeper Check-in"])

class CheckinScanRequest(BaseModel):
    tid: str
    tier: str
    ts: int
    nonce: str
    enc: str
    sig: str
    gate_id: str = "GATE-1A"
    staff_pin: str = "1234"

@router.post("")
def process_checkin(req: CheckinScanRequest):
    """
    Quy trình kiểm tra an ninh 5 bước tại cổng soát vé:
    1. Xác thực quyền nhân viên (Staff PIN: 1234).
    2. Chống DoS bằng Rate Limiter (tối đa 10 req/s/cổng).
    3. Chống Replay Attack: Kiểm tra thời hạn 30s và Nonce Cache.
    4. Chống Làm giả vé: Xác minh chữ ký số ECDSA P-256 bằng Public Key máy chủ.
    5. Chống Race Condition: Cập nhật nguyên tử CSDL (Atomic Conditional Update).
    """
    # Bước 1: Quyền nhân viên
    if req.staff_pin != "1234":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Mã PIN nhân viên không hợp lệ. Vui lòng đăng nhập lại."
        )

    # Bước 2: Rate Limiter (Chương 5 - DoS)
    if not app_state.security.check_rate_limit(req.gate_id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Tần suất quét quá dày đặc. Rate limit exceeded!"
        )

    # Bước 3: Chống Replay Attack (Chương 5)
    valid_time, time_msg = app_state.security.validate_timestamp_and_nonce(req.ts, req.nonce)
    if not valid_time:
        return {
            "success": False,
            "error_code": "REPLAY_ATTACK",
            "step_failed": "TIMESTAMP_OR_NONCE_EXPIRED",
            "message": time_msg
        }

    # Bước 4: Xác minh chữ ký số ECDSA (Chương 3)
    core_payload = {
        "tid": req.tid,
        "tier": req.tier,
        "ts": req.ts,
        "nonce": req.nonce,
        "enc": req.enc
    }
    
    is_sig_valid = app_state.crypto.verify_signature(core_payload, req.sig, app_state.pub_key_pem)
    if not is_sig_valid:
        return {
            "success": False,
            "error_code": "FORGERY_DETECTED",
            "step_failed": "ECDSA_SIGNATURE_MISMATCH",
            "message": "Chữ ký số ECDSA P-256 không hợp lệ hoặc dữ liệu vé không khớp."
        }

    # Giải mã thông tin người mua (Chương 1 & 2 - AES-GCM)
    decrypted_owner = app_state.crypto.decrypt_data(req.enc, app_state.aes_key)

    # Bước 5: Cập nhật nguyên tử CSDL chống Race Condition (Chương 4)
    db_success, db_msg = app_state.db.atomic_checkin(req.tid, req.gate_id)
    if not db_success:
        return {
            "success": False,
            "error_code": "ALREADY_USED_OR_RACE_CONDITION",
            "step_failed": "DB_ATOMIC_LOCK_FAILED",
            "message": db_msg,
            "owner": decrypted_owner
        }

    return {
        "success": True,
        "message": "CHECK-IN THÀNH CÔNG. MỜI KHÁCH VÀO CỬA!",
        "ticket_id": req.tid,
        "tier": req.tier,
        "owner": decrypted_owner,
        "gate_id": req.gate_id
    }
