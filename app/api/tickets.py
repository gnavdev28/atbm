import time
import os
import base64
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.core.config import app_state

router = APIRouter(prefix="/api/tickets", tags=["Tickets"])

class CreateTicketRequest(BaseModel):
    ticket_id: str
    owner_name: str
    citizen_id: str
    tier: str = "VIP PASS"

@router.post("")
def create_ticket(req: CreateTicketRequest):
    """Phát hành một vé điện tử mới, mã hóa thông tin người mua bằng AES-256-GCM"""
    enc_name = app_state.crypto.encrypt_data(
        {"full_name": req.owner_name, "citizen_id": req.citizen_id},
        app_state.aes_key
    )
    
    if app_state.db.get_ticket(req.ticket_id):
        raise HTTPException(status_code=400, detail="Mã vé đã tồn tại trong hệ thống")
        
    ticket = app_state.db.create_ticket(req.ticket_id, enc_name, req.tier)
    return {"status": "success", "ticket": ticket}

@router.get("/{ticket_id}")
def get_ticket(ticket_id: str):
    """Lấy thông tin vé và giải mã thông tin cá nhân người mua"""
    ticket = app_state.db.get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Không tìm thấy vé")
        
    decrypted_owner = app_state.crypto.decrypt_data(ticket["owner_name_enc"], app_state.aes_key)
    return {
        "id": ticket["id"],
        "tier": ticket["tier"],
        "status": ticket["status"],
        "created_at": ticket["created_at"],
        "used_at": ticket["used_at"],
        "owner": decrypted_owner
    }

@router.get("/{ticket_id}/qr")
def get_dynamic_qr(ticket_id: str):
    """
    Sinh mã QR động (Dynamic Rotating QR) xoay vòng mỗi 30 giây:
    1. Lấy timestamp hiện tại (epoch seconds).
    2. Sinh chuỗi ngẫu nhiên Nonce (8 bytes hex).
    3. Trích xuất thông tin vé từ CSDL.
    4. Ký số bằng Private Key ECDSA P-256 của máy chủ (SHA-256).
    """
    ticket = app_state.db.get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Không tìm thấy vé")

    now = int(time.time())
    nonce = os.urandom(8).hex()

    # Payload cốt lõi nhúng trong QR
    qr_payload = {
        "tid": ticket["id"],
        "tier": ticket["tier"],
        "ts": now,
        "nonce": nonce,
        "enc": ticket["owner_name_enc"]
    }

    # Ký số bằng Private Key của máy chủ
    sig = app_state.crypto.sign_payload(qr_payload, app_state.priv_key_pem)
    qr_payload["sig"] = sig

    return {
        "qr_payload": qr_payload,
        "expires_in_seconds": 30,
        "status": ticket["status"]
    }

@router.post("/{ticket_id}/reset")
def reset_ticket(ticket_id: str):
    """Đặt lại trạng thái vé về ACTIVE để phục vụ kiểm thử nhiều lần"""
    ticket = app_state.db.get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Không tìm thấy vé")
    app_state.db.reset_ticket(ticket_id)
    return {"status": "success", "message": f"Đã đặt lại trạng thái vé {ticket_id} về ACTIVE"}

