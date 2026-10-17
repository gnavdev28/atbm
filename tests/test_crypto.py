import pytest
from app.services.crypto_service import CryptoService

def test_generate_and_load_ecdsa_keys():
    """Kiểm tra sinh và nạp cặp khóa ECDSA P-256 chuẩn PEM"""
    crypto = CryptoService()
    priv_pem, pub_pem = crypto.generate_keypair()
    
    assert b"BEGIN EC PRIVATE KEY" in priv_pem or b"BEGIN PRIVATE KEY" in priv_pem
    assert b"BEGIN PUBLIC KEY" in pub_pem

def test_sign_and_verify_valid_payload():
    """Kiểm tra ký số ECDSA P-256 và xác minh chữ ký hợp lệ"""
    crypto = CryptoService()
    priv_pem, pub_pem = crypto.generate_keypair()
    
    payload = {
        "tid": "TK-98A4-2026",
        "tier": "VIP PASS",
        "ts": 1729160000,
        "nonce": "a1b2c3d4"
    }
    
    sig_b64 = crypto.sign_payload(payload, priv_pem)
    assert isinstance(sig_b64, str)
    assert len(sig_b64) > 0
    
    # Xác minh chữ ký số bằng Public Key
    is_valid = crypto.verify_signature(payload, sig_b64, pub_pem)
    assert is_valid is True

def test_verify_tampered_payload_fails():
    """Kiểm tra phát hiện giả mạo: Thay đổi dữ liệu vé làm chữ ký sai lệch"""
    crypto = CryptoService()
    priv_pem, pub_pem = crypto.generate_keypair()
    
    payload = {
        "tid": "TK-98A4-2026",
        "tier": "STANDARD",
        "ts": 1729160000,
        "nonce": "a1b2c3d4"
    }
    
    sig_b64 = crypto.sign_payload(payload, priv_pem)
    
    # Kẻ tấn công tự nâng hạng vé lên VIP
    tampered_payload = dict(payload)
    tampered_payload["tier"] = "VIP PASS"
    
    is_valid = crypto.verify_signature(tampered_payload, sig_b64, pub_pem)
    assert is_valid is False

def test_verify_corrupted_signature_fails():
    """Kiểm tra chữ ký số bị hỏng hoặc chữ ký giả mạo"""
    crypto = CryptoService()
    _, pub_pem = crypto.generate_keypair()
    
    payload = {"tid": "TK-1", "ts": 100, "nonce": "abc"}
    fake_sig = "MEQCIAfakeSignatureThatIsNotValid1234567890="
    
    is_valid = crypto.verify_signature(payload, fake_sig, pub_pem)
    assert is_valid is False

def test_aes_gcm_encrypt_and_decrypt():
    """Kiểm tra mã hóa và giải mã đối xứng xác thực AES-256-GCM"""
    crypto = CryptoService()
    aes_key = crypto.generate_aes_key() # 32 bytes (256 bits)
    
    personal_data = {
        "full_name": "Nguyễn Văn An",
        "citizen_id": "001202001234",
        "email": "an.nguyen@example.com"
    }
    
    encrypted_str = crypto.encrypt_data(personal_data, aes_key)
    assert isinstance(encrypted_str, str)
    assert "Nguyễn Văn An" not in encrypted_str  # Đã được bảo mật dữ liệu
    
    # Giải mã lại
    decrypted_data = crypto.decrypt_data(encrypted_str, aes_key)
    assert decrypted_data == personal_data
