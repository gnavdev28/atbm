import json
import base64
import os
from typing import Tuple, Dict, Any, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


class CryptoService:
    """
    Lõi Mật mã học (Core Cryptographic Engine)
    - Ký số & Xác minh: ECDSA đường cong NIST P-256 (SECP256R1) với SHA-256.
    - Bảo mật dữ liệu: Mã hóa đối xứng xác thực AES-256-GCM.
    """

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """
        Sinh cặp khóa ECDSA P-256 mới chuẩn định dạng PEM.
        Returns: (private_key_pem, public_key_pem)
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    @staticmethod
    def _canonicalize_payload(payload: Dict[str, Any]) -> bytes:
        """
        Chuẩn hóa dictionary thành chuỗi bytes bất biến (Deterministic Serialization)
        để đảm bảo cùng dữ liệu thì luôn ra cùng một chuỗi hash SHA-256.
        """
        return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')

    def sign_payload(self, payload: Dict[str, Any], private_key_pem: bytes) -> str:
        """
        Ký số lên payload bằng Private Key ECDSA P-256 (SHA-256).
        Returns: Chữ ký số mã hóa Base64 URL-safe.
        """
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        data_bytes = self._canonicalize_payload(payload)
        
        signature_der = private_key.sign(
            data_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return base64.urlsafe_b64encode(signature_der).decode('utf-8')

    def verify_signature(self, payload: Dict[str, Any], signature_b64: str, public_key_pem: bytes) -> bool:
        """
        Xác minh chữ ký số bằng Public Key ECDSA P-256.
        Returns: True nếu toàn vẹn & hợp lệ, False nếu bị chỉnh sửa dữ liệu hoặc chữ ký giả mạo.
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            signature_der = base64.urlsafe_b64decode(signature_b64.encode('utf-8'))
            data_bytes = self._canonicalize_payload(payload)
            
            public_key.verify(
                signature_der,
                data_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except (InvalidSignature, Exception):
            return False

    @staticmethod
    def generate_aes_key() -> bytes:
        """Sinh khóa đối xứng AES 256-bit (32 bytes)"""
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt_data(plain_dict: Dict[str, Any], key: bytes) -> str:
        """
        Mã hóa thông tin cá nhân bằng AES-256-GCM (Authenticated Encryption).
        Nonce ngẫu nhiên 96-bit (12 bytes) được ghép chung với ciphertext.
        """
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        data_bytes = json.dumps(plain_dict, ensure_ascii=False).encode('utf-8')
        
        ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
        # Kết hợp [12-byte Nonce] + [Ciphertext + 16-byte Auth Tag]
        return base64.urlsafe_b64encode(nonce + ciphertext).decode('utf-8')

    @staticmethod
    def decrypt_data(encrypted_str: str, key: bytes) -> Optional[Dict[str, Any]]:
        """
        Giải mã và kiểm tra tính toàn vẹn của dữ liệu bằng AES-256-GCM.
        Nếu dữ liệu bị sửa đổi, thuật toán GCM sẽ từ chối giải mã.
        """
        try:
            raw = base64.urlsafe_b64decode(encrypted_str.encode('utf-8'))
            if len(raw) < 12:
                return None
            nonce = raw[:12]
            ciphertext = raw[12:]
            
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode('utf-8'))
        except Exception:
            return None
