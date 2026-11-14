import json
from datetime import datetime, timezone
from fastapi import APIRouter, Header, HTTPException, status
from shared.crypto import RsaService, AesService, AesKey
from server.app.storage.memory_storage import MemoryStorage
from server.app.models.schemas import (
    SessionCreateRequest,
    SessionCreateResponse,
    SecureMessageRequest,
    SecureMessageResponse,
)

router = APIRouter(prefix="/api/secure", tags=["Secure Communication"])

storage: MemoryStorage = None
rsa_service: RsaService = None
aes_service: AesService = None


def init_secure(storage_instance: MemoryStorage, rsa_svc: RsaService, aes_svc: AesService):
    global storage, rsa_service, aes_service
    storage = storage_instance
    rsa_service = rsa_svc
    aes_service = aes_svc


@router.post(
    "/session",
    response_model=SessionCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Establish AES session using RSA-encrypted payload",
    responses={
        400: {"description": "Invalid payload or decryption failed"},
        404: {"description": "RSA key pair not found"},
    },
)
def create_session(
    body: SessionCreateRequest,
    x_rsa_id: int = Header(..., alias="x-rsa-id", description="ID of RSA key pair"),
):
    """
    Client sends RSA-encrypted JSON with session_id, aes_key, aes_iv.
    Server decrypts it with the private key corresponding to x-rsa-id
    and stores the AES key for the session.
    """
    rsa_keys = storage.get_rsa_keys(x_rsa_id)
    if rsa_keys is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"RSA key pair with id={x_rsa_id} not found",
        )

    try:
        decrypted = rsa_service.decrypt(rsa_keys.private_key, body.encrypted_payload)
        payload = json.loads(decrypted)
        session_id = payload["session_id"]
        aes_key_str = payload["aes_key"]
        aes_iv_str = payload["aes_iv"]
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to decrypt or parse session payload: {str(exc)}",
        )

    if not session_id or not aes_key_str or not aes_iv_str:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="session_id, aes_key and aes_iv are required in payload",
        )

    if storage.session_exists(session_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Session {session_id} already exists",
        )

    aes_key = AesKey(key=aes_key_str, iv=aes_iv_str)
    storage.store_session(session_id, aes_key)

    return SessionCreateResponse(
        status="ok",
        message="Session established successfully",
        session_id=session_id,
    )


@router.post(
    "/message",
    response_model=SecureMessageResponse,
    summary="Send encrypted message within an established session",
    responses={
        400: {"description": "Decryption/encryption failed"},
        404: {"description": "Session not found"},
    },
)
def send_secure_message(
    body: SecureMessageRequest,
    x_session_id: str = Header(..., alias="x-session-id", description="AES session ID"),
):
    """
    Client sends AES-encrypted message.
    Server decrypts it, appends reception timestamp, re-encrypts and returns.
    """
    aes_key = storage.get_session(x_session_id)
    if aes_key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session with id={x_session_id} not found",
        )

    try:
        plain = aes_service.decrypt(aes_key, body.encrypted_message)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to decrypt message: {str(exc)}",
        )

    # Append reception timestamp (UTC ISO format)
    received_at = datetime.now(timezone.utc).isoformat()
    response_text = f"{plain} [received_at={received_at}]"

    try:
        encrypted_response = aes_service.encrypt(aes_key, response_text)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to encrypt response: {str(exc)}",
        )

    return SecureMessageResponse(encrypted_response=encrypted_response)
