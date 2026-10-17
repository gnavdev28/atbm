from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from app.api import tickets, checkin, admin
from app.core.config import app_state

app = FastAPI(
    title="Secure QR Ticketing System",
    description="Hệ thống Phát hành Vé Điện tử QR Chống Giả mạo - Môn An Toàn Bảo Mật Thông Tin",
    version="1.0.0"
)

# Đăng ký các Router API
app.include_router(tickets.router)
app.include_router(checkin.router)
app.include_router(admin.router)

# Thư mục static cho giao diện web
static_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/", include_in_schema=False)
def serve_attendee_portal():
    """Cổng dành cho khách xem vé cá nhân"""
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/gatekeeper", include_in_schema=False)
def serve_gatekeeper_terminal():
    """Cổng máy quét camera của nhân viên an ninh"""
    return FileResponse(os.path.join(static_dir, "gatekeeper.html"))

@app.get("/admin", include_in_schema=False)
def serve_admin_security_lab():
    """Cổng Quản trị & Phòng thí nghiệm An ninh của giảng viên"""
    return FileResponse(os.path.join(static_dir, "admin.html"))
