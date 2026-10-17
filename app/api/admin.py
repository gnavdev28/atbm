import threading
import time
import json
import hashlib
import base64
import os
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from app.core.config import app_state

router = APIRouter(prefix="/api/admin", tags=["Security Lab & Admin"])

def verify_admin_auth(auth_token: str):
    if auth_token != "admin123":
        raise HTTPException(status_code=401, detail="Yêu cầu quyền Quản trị viên (admin123)")

class TamperAttackRequest(BaseModel):
    field_to_modify: str = "tier"
    new_value: str = "SUPER_VIP_HACKED"
    corrupt_signature: bool = False

class ReplayAttackRequest(BaseModel):
    age_seconds: int = 300
    duplicate_nonce: bool = False

class ConcurrencyAttackRequest(BaseModel):
    thread_count: int = 20

class CryptoEncryptRequest(BaseModel):
    full_name: str = "Nguyễn Văn An"
    citizen_id: str = "001202008899"

class CryptoDecryptRequest(BaseModel):
    encrypted_token: str

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

@router.get("/database-records")
def get_database_records(authorization: str = "admin123"):
    """Truy vấn trực tiếp CSDL SQLite: danh sách vé và nhật ký check-in thời gian thực"""
    verify_admin_auth(authorization)
    tickets = app_state.db.list_tickets(15)
    default_t = app_state.db.get_ticket(app_state.default_ticket_id)
    if default_t and not any(t["id"] == app_state.default_ticket_id for t in tickets):
        tickets.insert(0, default_t)
    for t in tickets:
        try:
            t["owner_decrypted"] = app_state.crypto.decrypt_data(t["owner_name_enc"], app_state.aes_key)
        except Exception:
            t["owner_decrypted"] = None

    logs = app_state.db.list_logs(20)
    return {
        "tickets": tickets,
        "logs": logs
    }

@router.post("/reset-ticket")
def reset_demo_ticket(authorization: str = "admin123"):
    """Đặt lại trạng thái vé demo về ACTIVE để phục vụ trình diễn nhiều lần"""
    verify_admin_auth(authorization)
    app_state.db.reset_ticket(app_state.default_ticket_id)
    return {"status": "success", "message": f"Đã đặt lại trạng thái vé {app_state.default_ticket_id} về ACTIVE"}

@router.post("/test-tamper")
def test_tamper_attack(req: Optional[TamperAttackRequest] = None, authorization: str = "admin123"):
    """
    KỊCH BẢN TẤN CÔNG 1: LÀM GIẢ NỘI DUNG VÉ (CHƯƠNG 3 - CHỮ KÝ SỐ)
    Cho phép can thiệp bất kỳ trường nào hoặc cố tình làm sai chữ ký số ECDSA.
    """
    verify_admin_auth(authorization)
    
    field = req.field_to_modify if req else "tier"
    new_val = req.new_value if req else "SUPER_VIP_HACKED"
    corrupt_sig = req.corrupt_signature if req else False

    # 1. Server ký vé Standard gốc
    original_payload = {
        "tid": "TK-ATTACK-001",
        "tier": "STANDARD",
        "ts": int(time.time()),
        "nonce": "tamper_test_nonce",
        "enc": "AES_ENC_DUMMY"
    }
    valid_sig = app_state.crypto.sign_payload(original_payload, app_state.priv_key_pem)

    # 2. Can thiệp nội dung
    tampered_payload = dict(original_payload)
    if corrupt_sig:
        # Giữ nguyên nội dung nhưng làm hỏng chữ ký (đổi 2 byte cuối)
        sig_to_verify = valid_sig[:-4] + "AAAA" if len(valid_sig) > 4 else "corrupted_sig"
        modified_desc = "Chữ ký số bị thay đổi/hỏng byte"
    else:
        tampered_payload[field] = new_val
        sig_to_verify = valid_sig
        modified_desc = f"{field}: '{original_payload.get(field, '')}' -> '{new_val}'"

    # 3. Tính toán SHA-256 hash của 2 bản tin để người học đối chiếu
    hash_orig = hashlib.sha256(json.dumps(original_payload, sort_keys=True).encode()).hexdigest()
    hash_tamp = hashlib.sha256(json.dumps(tampered_payload, sort_keys=True).encode()).hexdigest()

    # 4. Xác minh toán học ECDSA P-256
    is_valid = app_state.crypto.verify_signature(tampered_payload, sig_to_verify, app_state.pub_key_pem)

    return {
        "attack_name": "Tamper Payload Forgery",
        "attack_detected": not is_valid,
        "modified_field": modified_desc,
        "original_sha256": hash_orig[:16] + "...",
        "tampered_sha256": hash_tamp[:16] + "...",
        "ecdsa_verification_result": is_valid,
        "explanation": "Do hàm băm SHA-256 của nội dung bị thay đổi, chữ ký số ECDSA không khớp với Public Key máy chủ. Tấn công bị chặn đứng hoàn toàn."
    }

@router.post("/test-replay")
def test_replay_attack(req: Optional[ReplayAttackRequest] = None, authorization: str = "admin123"):
    """
    KỊCH BẢN TẤN CÔNG 2: TẤN CÔNG PHÁT LẠI (CHƯƠNG 5 - AN NINH MẠNG)
    Gửi mã có độ tuổi tuỳ chỉnh hoặc cố tình gửi lại Nonce đã nằm trong NonceCache.
    """
    verify_admin_auth(authorization)
    
    age = req.age_seconds if req else 300
    dup_nonce = req.duplicate_nonce if req else False

    test_timestamp = int(time.time()) - age
    nonce = f"nonce_test_{int(time.time())}"

    if dup_nonce:
        # Đưa trước nonce vào cache để mô phỏng phát lại gói tin
        app_state.security.nonce_cache[nonce] = time.time() + 60
        age = 10  # Timestamp vẫn trong ngưỡng 30s nhưng Nonce bị trùng
        test_timestamp = int(time.time()) - age

    is_valid, reason = app_state.security.validate_timestamp_and_nonce(test_timestamp, nonce)

    return {
        "attack_name": "Replay Attack",
        "attack_detected": not is_valid,
        "timestamp_age_seconds": age,
        "allowed_threshold_seconds": 30,
        "duplicate_nonce_tested": dup_nonce,
        "server_response": reason,
        "explanation": "Hệ thống kiểm tra cửa sổ trượt (30s) và bộ đệm NonceCache (TTL 60s). Mã cũ hoặc Nonce đã dùng đều bị từ chối."
    }

@router.post("/test-concurrency")
def test_concurrency_attack(req: Optional[ConcurrencyAttackRequest] = None, authorization: str = "admin123"):
    """
    KỊCH BẢN TẤN CÔNG 3: TRANH CHẤP ĐỒNG THỜI (CHƯƠNG 4 - AN TOÀN CSDL)
    Giả lập N cổng quét nã request check-in cùng 1 mili-giây cho 1 vé hợp lệ.
    """
    verify_admin_auth(authorization)
    
    count = req.thread_count if req else 20
    count = max(2, min(50, count))

    concurrency_ticket_id = f"TK-FLOOD-{int(time.time()*1000)}"
    flood_owner_enc = app_state.crypto.encrypt_data({
        "full_name": f"Khách Đua Tranh #{str(int(time.time()*1000))[-4:]}",
        "citizen_id": "038202008899"
    }, app_state.aes_key)
    app_state.db.create_ticket(concurrency_ticket_id, flood_owner_enc, "VIP PASS")

    results = []
    threads = []
    t_start = time.perf_counter()

    def worker(worker_id):
        success, msg = app_state.db.atomic_checkin(concurrency_ticket_id, gate_id=f"GATE-{worker_id}")
        results.append({
            "worker_id": worker_id,
            "success": success,
            "message": msg
        })

    for i in range(1, count + 1):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    duration_ms = round((time.perf_counter() - t_start) * 1000, 2)
    success_count = sum(1 for r in results if r["success"] is True)
    failed_count = sum(1 for r in results if r["success"] is False)

    return {
        "attack_name": f"Concurrency Flood ({count} Parallel Gates)",
        "total_requests": count,
        "success_admitted": success_count,
        "rejected_blocked": failed_count,
        "duration_ms": duration_ms,
        "results_details": sorted(results, key=lambda x: x["worker_id"]),
        "explanation": "Câu lệnh UPDATE nguyên tử trong ACID transaction đảm bảo chỉ duy nhất 1 luồng nhận rowcount == 1, các luồng còn lại bị từ chối. Triệt tiêu hoàn toàn Race Condition."
    }

@router.post("/crypto-lab/encrypt")
def crypto_lab_encrypt(req: CryptoEncryptRequest, authorization: str = "admin123"):
    """Trực quan hóa thuật toán mã hóa xác thực AES-256-GCM"""
    verify_admin_auth(authorization)
    plain_dict = {"full_name": req.full_name, "citizen_id": req.citizen_id}
    token = app_state.crypto.encrypt_data(plain_dict, app_state.aes_key)
    
    # Giải mã Base64 URL-safe có bù padding: [12 bytes Nonce] + [Ciphertext] + [16 bytes MAC Tag]
    pad = '=' * (-len(token) % 4)
    raw = base64.urlsafe_b64decode((token + pad).encode('utf-8'))
    nonce_hex = raw[:12].hex()
    tag_hex = raw[-16:].hex()
    ct_hex = raw[12:-16].hex()

    return {
        "status": "success",
        "cipher": "AES-256-GCM",
        "plaintext": plain_dict,
        "nonce_hex": nonce_hex,
        "tag_hex": tag_hex,
        "ciphertext_hex": ct_hex[:32] + "...",
        "combined_token": token
    }

@router.post("/crypto-lab/decrypt")
def crypto_lab_decrypt(req: CryptoDecryptRequest, authorization: str = "admin123"):
    """Trực quan hóa giải mã xác thực và kiểm tra tính toàn vẹn MAC Tag AES-256-GCM"""
    verify_admin_auth(authorization)
    try:
        decrypted = app_state.crypto.decrypt_data(req.encrypted_token, app_state.aes_key)
        if not decrypted:
            return {
                "success": False,
                "mac_tag_valid": False,
                "decrypted_data": None,
                "message": "Giải mã thất bại hoặc dữ liệu bị sửa đổi (MAC Tag Invalid)"
            }
        return {
            "success": True,
            "mac_tag_valid": True,
            "decrypted_data": decrypted,
            "message": "Toàn vẹn dữ liệu được đảm bảo (128-bit MAC Tag hợp lệ)"
        }
    except Exception as e:
        return {
            "success": False,
            "mac_tag_valid": False,
            "decrypted_data": None,
            "message": f"Giải mã thất bại hoặc dữ liệu bị sửa đổi (MAC Tag Invalid): {str(e)}"
        }

class GenerateTamperedQrRequest(BaseModel):
    ticket_id: Optional[str] = "TK-VIP-001"
    field_to_modify: str = "tier"
    new_value: str = "SUPER_VIP_HACKED"
    corrupt_signature: bool = False

@router.post("/generate-tampered-qr")
def generate_tampered_qr(req: Optional[GenerateTamperedQrRequest] = None, authorization: str = "admin123"):
    """
    Sinh gói tin và mã QR giả mạo thật sự để người dùng tải về quét tại Cổng Soát Vé.
    """
    verify_admin_auth(authorization)
    tid = req.ticket_id if (req and req.ticket_id) else "TK-VIP-001"
    field = req.field_to_modify if req else "tier"
    new_val = req.new_value if req else "SUPER_VIP_HACKED"
    corrupt_sig = req.corrupt_signature if req else False

    ticket = app_state.db.get_ticket(tid)
    enc_data = ticket["owner_name_enc"] if ticket else "ENC_DUMMY_DATA"
    tier = ticket["tier"] if ticket else "VIP PASS"

    original_payload = {
        "tid": tid,
        "tier": tier,
        "ts": int(time.time()),
        "nonce": os.urandom(8).hex(),
        "enc": enc_data
    }
    valid_sig = app_state.crypto.sign_payload(original_payload, app_state.priv_key_pem)

    tampered_payload = dict(original_payload)
    if corrupt_sig:
        tampered_sig = valid_sig[:-4] + "AAAA" if len(valid_sig) > 4 else "BAD_SIG_123"
        tampered_desc = "Cố tình làm sai lệch 2 byte cuối chữ ký số ECDSA"
    else:
        tampered_payload[field] = new_val
        tampered_sig = valid_sig
        tampered_desc = f"Sửa trường '{field}' thành '{new_val}' nhưng giữ chữ ký cũ"

    tampered_payload["sig"] = tampered_sig

    hash_orig = hashlib.sha256(json.dumps(original_payload, sort_keys=True).encode()).hexdigest()
    hash_tamp = hashlib.sha256(json.dumps({k: v for k, v in tampered_payload.items() if k != "sig"}, sort_keys=True).encode()).hexdigest()
    is_valid = app_state.crypto.verify_signature({k: v for k, v in tampered_payload.items() if k != "sig"}, tampered_sig, app_state.pub_key_pem)

    return {
        "status": "success",
        "tampered_payload": tampered_payload,
        "original_payload": original_payload,
        "tampered_desc": tampered_desc,
        "tampered_json": json.dumps(tampered_payload),
        "original_sha256": hash_orig,
        "tampered_sha256": hash_tamp,
        "ecdsa_valid": is_valid
    }

class GenerateExpiredQrRequest(BaseModel):
    ticket_id: Optional[str] = "TK-VIP-001"
    age_seconds: int = 60

@router.post("/generate-expired-qr")
def generate_expired_qr(req: Optional[GenerateExpiredQrRequest] = None, authorization: str = "admin123"):
    """
    Sinh mã QR hợp lệ nhưng bị lùi timestamp về quá khứ (vượt quá 30 giây TTL).
    """
    verify_admin_auth(authorization)
    tid = req.ticket_id if (req and req.ticket_id) else "TK-VIP-001"
    age = req.age_seconds if req else 60

    ticket = app_state.db.get_ticket(tid)
    enc_data = ticket["owner_name_enc"] if ticket else "ENC_DUMMY_DATA"
    tier = ticket["tier"] if ticket else "VIP PASS"

    expired_payload = {
        "tid": tid,
        "tier": tier,
        "ts": int(time.time()) - age,
        "nonce": os.urandom(8).hex(),
        "enc": enc_data
    }
    sig = app_state.crypto.sign_payload(expired_payload, app_state.priv_key_pem)
    expired_payload["sig"] = sig

    return {
        "status": "success",
        "expired_payload": expired_payload,
        "age_seconds": age,
        "expired_json": json.dumps(expired_payload)
    }

