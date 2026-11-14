import pytest
from shared.crypto import AesService, AesKey


@pytest.fixture
def aes_service():
    return AesService()


def test_generate_secret_key(aes_service):
    key = aes_service.generate_secret_key()
    assert isinstance(key, AesKey)
    assert key.key
    assert key.iv
    assert key.key != key.iv


def test_encrypt_decrypt_roundtrip(aes_service):
    key = aes_service.generate_secret_key()
    plain = "Секретне повідомлення для AES 123!"
    cipher = aes_service.encrypt(key, plain)
    assert cipher != plain
    decrypted = aes_service.decrypt(key, cipher)
    assert decrypted == plain


def test_encrypt_produces_base64(aes_service):
    key = aes_service.generate_secret_key()
    cipher = aes_service.encrypt(key, "test data")
    import base64
    base64.b64decode(cipher)


def test_decrypt_invalid_cipher_raises(aes_service):
    key = aes_service.generate_secret_key()
    with pytest.raises(Exception):
        aes_service.decrypt(key, "invalid-cipher-text!!!")


def test_different_keys_produce_different_cipher(aes_service):
    key1 = aes_service.generate_secret_key()
    key2 = aes_service.generate_secret_key()
    plain = "same message"
    c1 = aes_service.encrypt(key1, plain)
    c2 = aes_service.encrypt(key2, plain)
    assert c1 != c2
