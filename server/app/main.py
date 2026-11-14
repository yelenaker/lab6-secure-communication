from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from shared.crypto import RsaService, AesService
from server.app.storage.memory_storage import MemoryStorage
from server.app.api import crypto_keys, secure
from server.app.models.schemas import HealthResponse

app = FastAPI(
    title="Lab 6 – Secure Communication API",
    description=(
        "Web API that provides RSA key management and a simple RSA+AES "
        "secure communication channel between client and server. "
        "This is an educational illustration, not a production TLS implementation."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared instances
storage = MemoryStorage()
rsa_service = RsaService()
aes_service = AesService()

# Pre-generate a few RSA key pairs at startup (as suggested by sequence diagram)
for _ in range(10):
    keys = rsa_service.generate_crypto_keys()
    storage.store_rsa_keys(keys)

crypto_keys.init_crypto_keys(storage, rsa_service)
secure.init_secure(storage, rsa_service, aes_service)

app.include_router(crypto_keys.router)
app.include_router(secure.router)


@app.get("/health", response_model=HealthResponse, tags=["Health"])
def health():
    return HealthResponse()


@app.get("/", tags=["Health"])
def root():
    return {
        "message": "Lab 6 Secure Communication API is running",
        "docs": "/docs",
        "health": "/health",
    }
