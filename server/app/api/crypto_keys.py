from fastapi import APIRouter, HTTPException, status
from shared.crypto import RsaService
from server.app.storage.memory_storage import MemoryStorage
from server.app.models.schemas import GenerateRsaKeysResponse, RsaPublicKeyResponse

router = APIRouter(prefix="/api/crypto-keys", tags=["Crypto Keys"])

# Will be injected via dependency or global in main
storage: MemoryStorage = None
rsa_service: RsaService = None


def init_crypto_keys(storage_instance: MemoryStorage, rsa_svc: RsaService):
    global storage, rsa_service
    storage = storage_instance
    rsa_service = rsa_svc


@router.post(
    "/generate/rsa-keys",
    response_model=GenerateRsaKeysResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate RSA key pair",
    responses={
        400: {"description": "Key generation failed"},
    },
)
def generate_rsa_keys():
    """
    Generates an RSA private/public key pair, stores it in memory,
    and returns the integer identifier of the pair.
    """
    try:
        keys = rsa_service.generate_crypto_keys()
        key_id = storage.store_rsa_keys(keys)
        return GenerateRsaKeysResponse(id=key_id)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to generate RSA keys: {str(exc)}",
        )


@router.get(
    "/rsa-public-key/{key_id}",
    response_model=RsaPublicKeyResponse,
    summary="Get RSA public key by ID",
    responses={
        404: {"description": "Key pair with given ID not found"},
    },
)
def get_rsa_public_key(key_id: int):
    """
    Returns the Base64-encoded RSA public key for the given key pair ID.
    """
    public_key = storage.get_rsa_public_key(key_id)
    if public_key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"RSA key pair with id={key_id} not found",
        )
    return RsaPublicKeyResponse(id=key_id, public_key=public_key)
