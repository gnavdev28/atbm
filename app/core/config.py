import os
from typing import Tuple
from app.services.crypto_service import CryptoService
from app.services.security_service import SecurityService
from app.db.database import DatabaseService

class AppState:
    """Singleton quản lý trạng thái, cặp khóa bảo mật và cơ sở dữ liệu của server"""
    def __init__(self, db_path: str = "secure_ticketing.db"):
        self.crypto = CryptoService()
        self.security = SecurityService(window_seconds=30, nonce_ttl=60, rate_limit_per_second=10)
        self.db = DatabaseService(db_path=db_path)
        self.db.init_schema()

        # Quản lý khóa mật mã kiên cố (Persistent Key Store)
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        keys_dir = os.path.join(base_dir, ".keys")
        os.makedirs(keys_dir, exist_ok=True)
        
        priv_path = os.path.join(keys_dir, "server_ecdsa.pem")
        pub_path = os.path.join(keys_dir, "server_ecdsa_pub.pem")
        aes_path = os.path.join(keys_dir, "server_aes.key")

        if os.path.exists(priv_path) and os.path.exists(pub_path) and os.path.exists(aes_path):
            with open(priv_path, "rb") as f:
                self.priv_key_pem = f.read()
            with open(pub_path, "rb") as f:
                self.pub_key_pem = f.read()
            with open(aes_path, "rb") as f:
                self.aes_key = f.read()
        else:
            self.priv_key_pem, self.pub_key_pem = self.crypto.generate_keypair()
            self.aes_key = self.crypto.generate_aes_key()
            with open(priv_path, "wb") as f:
                f.write(self.priv_key_pem)
            with open(pub_path, "wb") as f:
                f.write(self.pub_key_pem)
            with open(aes_path, "wb") as f:
                f.write(self.aes_key)

        # Tạo / Làm mới vé mặc định với khóa AES hợp lệ
        self.default_ticket_id = "TK-98A4-2026"
        enc_name = self.crypto.encrypt_data({"full_name": "Nguyễn Văn An", "cid": "001202001234"}, self.aes_key)
        
        existing = self.db.get_ticket(self.default_ticket_id)
        if not existing:
            self.db.create_ticket(self.default_ticket_id, enc_name, tier="VIP PASS")
        else:
            # Cập nhật lại owner_name_enc đảm bảo tương thích với khóa AES
            with self.db.get_connection() as conn:
                conn.execute(
                    "UPDATE tickets SET owner_name_enc = ? WHERE id = ?;",
                    (enc_name, self.default_ticket_id)
                )
                conn.commit()

app_state = AppState()
