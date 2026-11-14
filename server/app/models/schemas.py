from pydantic import BaseModel, Field
from typing import Optional


class GenerateRsaKeysResponse(BaseModel):
    id: int = Field(..., description="Integer identifier of the generated RSA key pair")


class RsaPublicKeyResponse(BaseModel):
    id: int
    public_key: str = Field(..., description="Base64-encoded RSA public key (PEM)")


class SessionCreateRequest(BaseModel):
    encrypted_payload: str = Field(
        ...,
        description="Base64-encoded RSA-encrypted JSON containing session_id, aes_key, aes_iv",
    )


class SessionCreateResponse(BaseModel):
    status: str = "ok"
    message: str = "Session established successfully"
    session_id: str


class SecureMessageRequest(BaseModel):
    encrypted_message: str = Field(
        ..., description="Base64-encoded AES-encrypted message"
    )


class SecureMessageResponse(BaseModel):
    encrypted_response: str = Field(
        ..., description="Base64-encoded AES-encrypted response from server"
    )


class ErrorResponse(BaseModel):
    detail: str


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "lab6-secure-api"
