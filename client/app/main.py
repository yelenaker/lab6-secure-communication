#!/usr/bin/env python3
"""
Console client for Lab 6 – Secure Communication with RSA + AES.
"""

import json
import os
import sys
import uuid
import requests

# Allow running both from project root and from inside Docker
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from shared.crypto import RsaService, AesService, AesKey


SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:8000")


def get_rsa_public_key(session: requests.Session) -> tuple[int, str]:
    """Request a new RSA key pair and return (id, public_key)."""
    resp = session.post(f"{SERVER_URL}/api/crypto-keys/generate/rsa-keys")
    resp.raise_for_status()
    key_id = resp.json()["id"]

    resp = session.get(f"{SERVER_URL}/api/crypto-keys/rsa-public-key/{key_id}")
    resp.raise_for_status()
    public_key = resp.json()["public_key"]
    return key_id, public_key


def establish_session(
    session: requests.Session,
    rsa_service: RsaService,
    aes_service: AesService,
    key_id: int,
    public_key: str,
) -> tuple[str, AesKey]:
    """Generate AES key, encrypt session data with RSA, send to server."""
    aes_key = aes_service.generate_secret_key()
    session_id = str(uuid.uuid4())

    payload = {
        "session_id": session_id,
        "aes_key": aes_key.key,
        "aes_iv": aes_key.iv,
    }
    plain = json.dumps(payload)
    encrypted_payload = rsa_service.encrypt(public_key, plain)

    headers = {"x-rsa-id": str(key_id)}
    resp = session.post(
        f"{SERVER_URL}/api/secure/session",
        json={"encrypted_payload": encrypted_payload},
        headers=headers,
    )
    resp.raise_for_status()
    data = resp.json()
    print(f"[OK] Сесію встановлено. Session ID: {data['session_id']}")
    return session_id, aes_key


def send_message(
    session: requests.Session,
    aes_service: AesService,
    session_id: str,
    aes_key: AesKey,
    message: str,
) -> str:
    """Encrypt message with AES, send to server, decrypt response."""
    encrypted = aes_service.encrypt(aes_key, message)
    headers = {"x-session-id": session_id}
    resp = session.post(
        f"{SERVER_URL}/api/secure/message",
        json={"encrypted_message": encrypted},
        headers=headers,
    )
    resp.raise_for_status()
    encrypted_response = resp.json()["encrypted_response"]
    decrypted = aes_service.decrypt(aes_key, encrypted_response)
    return decrypted


def main():
    print("=" * 60)
    print("  Lab 6 – Безпечна комунікація (RSA + AES)")
    print("=" * 60)
    print(f"Сервер: {SERVER_URL}")
    print("Введіть повідомлення для відправки. Команда 'exit' — вихід.\n")

    http = requests.Session()
    rsa_service = RsaService()
    aes_service = AesService()

    # Step 1–5: obtain RSA public key and establish AES session once
    try:
        print("Отримую RSA public key з сервера...")
        key_id, public_key = get_rsa_public_key(http)
        print(f"[OK] Отримано RSA public key (id={key_id})")

        print("Створюю AES session...")
        session_id, aes_key = establish_session(
            http, rsa_service, aes_service, key_id, public_key
        )
    except requests.RequestException as e:
        print(f"[ПОМИЛКА] Не вдалося встановити з'єднання з сервером: {e}")
        sys.exit(1)

    # Main loop – reuse the same session for multiple messages
    while True:
        try:
            user_input = input("\nВаше повідомлення > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nВихід.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "q"):
            print("Вихід.")
            break

        try:
            response = send_message(http, aes_service, session_id, aes_key, user_input)
            print("-" * 50)
            print(f"Session ID : {session_id}")
            print(f"Ваше повідомлення : {user_input}")
            print(f"Відповідь сервера  : {response}")
            print("-" * 50)
        except requests.RequestException as e:
            print(f"[ПОМИЛКА] Помилка комунікації: {e}")
        except Exception as e:
            print(f"[ПОМИЛКА] {e}")


if __name__ == "__main__":
    main()
