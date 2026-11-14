import pytest
from shared.crypto import RsaService, RsaKeys


@pytest.fixture
def rsa_service():
    return RsaService()


def test_generate_crypto_keys(rsa_service):
    keys = rsa_service.generate_crypto_keys()
    assert isinstance(keys, RsaKeys)
    assert keys.public_key
    assert keys.private_key
    assert keys.public_key != keys.private_key


def test_encrypt_decrypt_roundtrip(rsa_service):
    keys = rsa_service.generate_crypto_keys()
    plain = "Hello, Lab 6! Secure message 🔒"
    cipher = rsa_service.encrypt(keys.public_key, plain)
    assert cipher != plain
    decrypted = rsa_service.decrypt(keys.private_key, cipher)
    assert decrypted == plain


def test_encrypt_produces_base64(rsa_service):
    keys = rsa_service.generate_crypto_keys()
    cipher = rsa_service.encrypt(keys.public_key, "test")
    # Should be valid base64
    import base64
    base64.b64decode(cipher)


def test_decrypt_invalid_cipher_raises(rsa_service):
    keys = rsa_service.generate_crypto_keys()
    with pytest.raises(Exception):
        rsa_service.decrypt(keys.private_key, "not-valid-base64-cipher!!!")
