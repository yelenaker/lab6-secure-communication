from pydantic import BaseModel


class RsaKeys(BaseModel):
    public_key: str
    private_key: str


class AesKey(BaseModel):
    key: str
    iv: str
