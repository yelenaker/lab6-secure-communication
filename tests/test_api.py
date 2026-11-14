import pytest
from fastapi.testclient import TestClient
from server.app.main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_generate_rsa_keys():
    r = client.post("/api/crypto-keys/generate/rsa-keys")
    assert r.status_code == 201
    data = r.json()
    assert "id" in data
    assert isinstance(data["id"], int)
    assert data["id"] > 0


def test_get_rsa_public_key():
    # Generate first
    r = client.post("/api/crypto-keys/generate/rsa-keys")
    key_id = r.json()["id"]

    r = client.get(f"/api/crypto-keys/rsa-public-key/{key_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == key_id
    assert data["public_key"]
    # Base64-ish
    assert len(data["public_key"]) > 100


def test_get_rsa_public_key_not_found():
    r = client.get("/api/crypto-keys/rsa-public-key/999999")
    assert r.status_code == 404


def test_full_secure_flow():
    from shared.crypto import RsaService, AesService
    import json
    import uuid

    rsa = RsaService()
    aes = AesService()

    # 1. Generate RSA keys
    r = client.post("/api/crypto-keys/generate/rsa-keys")
    assert r.status_code == 201
    key_id = r.json()["id"]

    # 2. Get public key
    r = client.get(f"/api/crypto-keys/rsa-public-key/{key_id}")
    assert r.status_code == 200
    public_key = r.json()["public_key"]

    # 3. Create AES key + session payload
    aes_key = aes.generate_secret_key()
    session_id = str(uuid.uuid4())
    payload = {
        "session_id": session_id,
        "aes_key": aes_key.key,
        "aes_iv": aes_key.iv,
    }
    encrypted_payload = rsa.encrypt(public_key, json.dumps(payload))

    # 4. Establish session
    r = client.post(
        "/api/secure/session",
        json={"encrypted_payload": encrypted_payload},
        headers={"x-rsa-id": str(key_id)},
    )
    assert r.status_code == 201
    assert r.json()["session_id"] == session_id

    # 5. Send encrypted message
    message = "Hello secure world!"
    encrypted_msg = aes.encrypt(aes_key, message)
    r = client.post(
        "/api/secure/message",
        json={"encrypted_message": encrypted_msg},
        headers={"x-session-id": session_id},
    )
    assert r.status_code == 200
    encrypted_response = r.json()["encrypted_response"]

    # 6. Decrypt response
    decrypted = aes.decrypt(aes_key, encrypted_response)
    assert message in decrypted
    assert "received_at=" in decrypted


def test_session_not_found():
    r = client.post(
        "/api/secure/message",
        json={"encrypted_message": "whatever"},
        headers={"x-session-id": "non-existent-session"},
    )
    assert r.status_code == 404
