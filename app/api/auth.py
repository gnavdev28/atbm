from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Dict, Any

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

class LoginRequest(BaseModel):
    username: str
    password: str

ACCOUNTS = {
    "khach": {
        "password": "khach123",
        "role": "guest",
        "name": "Nguyễn Văn An (Người Tham Dự)",
        "redirect_url": "/"
    },
    "guest": {
        "password": "guest123",
        "role": "guest",
        "name": "Nguyễn Văn An (Người Tham Dự)",
        "redirect_url": "/"
    },
    "baove": {
        "password": "1234",
        "role": "guard",
        "name": "Đội An Ninh (Cổng 1A)",
        "staff_pin": "1234",
        "redirect_url": "/gatekeeper"
    },
    "guard": {
        "password": "1234",
        "role": "guard",
        "name": "Đội An Ninh (Cổng 1A)",
        "staff_pin": "1234",
        "redirect_url": "/gatekeeper"
    },
    "admin": {
        "password": "admin123",
        "role": "admin",
        "name": "Quản Trị Viên (Admin & Lab)",
        "token": "admin123",
        "redirect_url": "/admin"
    }
}

@router.post("/login")
def login(req: LoginRequest):
    u = req.username.strip().lower()
    p = req.password.strip()
    
    account = ACCOUNTS.get(u)
    if not account or account["password"] != p:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tên đăng nhập hoặc mật khẩu không chính xác!"
        )
    
    return {
        "status": "success",
        "username": u,
        "role": account["role"],
        "name": account["name"],
        "redirect_url": account["redirect_url"],
        "token": account.get("token", ""),
        "staff_pin": account.get("staff_pin", "")
    }

@router.get("/demo-accounts")
def get_demo_accounts():
    """Danh sách tài khoản demo cho 3 cấp độ kiểm thử"""
    return [
        {
            "level": 1,
            "role": "guest",
            "title": "Cấp 1: Khách Tham Dự",
            "desc": "Chỉ xem vé cá nhân & mã QR động (Trang 1)",
            "username": "khach",
            "password": "khach123",
            "redirect_url": "/"
        },
        {
            "level": 2,
            "role": "guard",
            "title": "Cấp 2: Bảo Vệ Cổng",
            "desc": "Chỉ thao tác quét QR camera & kiểm soát check-in (Trang 2)",
            "username": "baove",
            "password": "1234",
            "redirect_url": "/gatekeeper"
        },
        {
            "level": 3,
            "role": "admin",
            "title": "Cấp 3: Quản Trị Viên (Admin)",
            "desc": "Hiện cả 3 cấp độ để test, kiểm thử tấn công & crypto lab",
            "username": "admin",
            "password": "admin123",
            "redirect_url": "/admin"
        }
    ]
