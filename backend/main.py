from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from aes_teaching import (
    encrypt_block_with_steps,
    expand_key_with_steps,
    avalanche_analysis,
    multi_trial_avalanche_experiment
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import base64
import os


app = FastAPI(
    title="Cryptography GUI API",
    description="Dockerized API for demonstrating cryptographic algorithms",
    version="1.0"
)


# -------------------------
# Request Models
# -------------------------

class EncryptRequest(BaseModel):
    plaintext: str
    key: str


class DecryptRequest(BaseModel):
    ciphertext: str
    nonce: str
    key: str

class AESTeachingRequest(BaseModel):
    plaintext_hex: str
    key_hex: str	

class AESKeyExpansionRequest(BaseModel):
    key_hex: str

class AESAvalancheRequest(BaseModel):
    plaintext_hex: str
    key_hex: str
    experiment_type: str
    bit_index: int

class AESLabExperimentRequest(BaseModel):
    plaintext_hex: str
    key_hex: str
    experiment_type: str
    start_bit: int
    end_bit: int

# -------------------------
# Basic API
# -------------------------

@app.get("/")
def home():
    return {
        "message": "Cryptography API is running",
        "status": "success"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# -------------------------
# AES Key Generator
# -------------------------

@app.get("/aes/generate-key")
def generate_key():

    key = AESGCM.generate_key(bit_length=128)

    encoded_key = base64.b64encode(key).decode("utf-8")

    return {
        "algorithm": "AES-128-GCM",
        "key": encoded_key
    }


# -------------------------
# AES Encryption
# -------------------------

@app.post("/aes/encrypt")
def encrypt(data: EncryptRequest):

    try:

        key = base64.b64decode(data.key, validate=True)

        if len(key) != 16:
            raise ValueError("AES-128 requires a 16-byte key")

        aesgcm = AESGCM(key)

        nonce = os.urandom(12)

        plaintext_bytes = data.plaintext.encode("utf-8")

        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext_bytes,
            None
        )

        return {
            "algorithm": "AES-128-GCM",

            "plaintext": data.plaintext,

            "ciphertext":
                base64.b64encode(ciphertext).decode("utf-8"),

            "nonce":
                base64.b64encode(nonce).decode("utf-8")
        }

    except Exception as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


# -------------------------
# AES Decryption
# -------------------------

@app.post("/aes/decrypt")
def decrypt(data: DecryptRequest):

    try:

        key = base64.b64decode(data.key, validate=True)

        if len(key) != 16:
            raise ValueError("AES-128 requires a 16-byte key")

        nonce = base64.b64decode(
            data.nonce,
            validate=True
        )

        if len(nonce) != 12:
            raise ValueError(
                "AES-GCM requires a 12-byte nonce"
            )

        ciphertext = base64.b64decode(
            data.ciphertext,
            validate=True
        )

        aesgcm = AESGCM(key)

        plaintext = aesgcm.decrypt(
            nonce,
            ciphertext,
            None
        )

        return {
            "algorithm": "AES-128-GCM",

            "plaintext":
                plaintext.decode("utf-8")
        }

    except Exception as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

# ---------------------------------------------------------
# AES EDUCATIONAL VISUALIZATION
# ---------------------------------------------------------

@app.post("/aes/visualize")
def visualize_aes(
    data: AESTeachingRequest
):

    try:

        plaintext_hex = (
            data.plaintext_hex
            .replace(" ", "")
            .strip()
        )

        key_hex = (
            data.key_hex
            .replace(" ", "")
            .strip()
        )

        if len(plaintext_hex) != 32:
            raise ValueError(
                "Plaintext must contain exactly "
                "32 hexadecimal characters (16 bytes)"
            )

        if len(key_hex) != 32:
            raise ValueError(
                "AES-128 key must contain exactly "
                "32 hexadecimal characters (16 bytes)"
            )

        try:
            plaintext = bytes.fromhex(
                plaintext_hex
            )

            key = bytes.fromhex(
                key_hex
            )

        except ValueError:
            raise ValueError(
                "Plaintext and key must contain "
                "valid hexadecimal characters only"
            )

        result = encrypt_block_with_steps(
            plaintext,
            key
        )

        return result

    except Exception as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )	

@app.post("/aes/key-expansion")
def aes_key_expansion(
    request: AESKeyExpansionRequest
):

    key_hex = (
        request.key_hex
        .replace(" ", "")
        .strip()
    )

    if len(key_hex) != 32:

        raise HTTPException(
            status_code=400,
            detail=(
                "AES-128 key must contain "
                "exactly 32 hexadecimal characters."
            )
        )

    try:

        key_bytes = bytes.fromhex(
            key_hex
        )

    except ValueError:

        raise HTTPException(
            status_code=400,
            detail=(
                "AES-128 key must contain "
                "hexadecimal characters only."
            )
        )

    try:

        return expand_key_with_steps(
            key_bytes
        )

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

@app.post("/aes/avalanche")
def aes_avalanche(
    request: AESAvalancheRequest
):

    plaintext_hex = (
        request.plaintext_hex
        .replace(" ", "")
        .strip()
    )

    key_hex = (
        request.key_hex
        .replace(" ", "")
        .strip()
    )

    # --------------------------------------------------------
    # LENGTH VALIDATION
    # --------------------------------------------------------

    if len(plaintext_hex) != 32:

        raise HTTPException(
            status_code=400,
            detail=(
                "Plaintext must contain exactly "
                "32 hexadecimal characters."
            )
        )

    if len(key_hex) != 32:

        raise HTTPException(
            status_code=400,
            detail=(
                "AES-128 key must contain exactly "
                "32 hexadecimal characters."
            )
        )

    # --------------------------------------------------------
    # HEX VALIDATION
    # --------------------------------------------------------

    try:

        plaintext_bytes = bytes.fromhex(
            plaintext_hex
        )

    except ValueError:

        raise HTTPException(
            status_code=400,
            detail=(
                "Plaintext must contain hexadecimal "
                "characters only."
            )
        )

    try:

        key_bytes = bytes.fromhex(
            key_hex
        )

    except ValueError:

        raise HTTPException(
            status_code=400,
            detail=(
                "Key must contain hexadecimal "
                "characters only."
            )
        )

    # --------------------------------------------------------
    # EXPERIMENT VALIDATION
    # --------------------------------------------------------

    experiment_type = (
        request.experiment_type
        .strip()
        .lower()
    )

    if experiment_type not in (
        "plaintext",
        "key"
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "experiment_type must be "
                "'plaintext' or 'key'."
            )
        )

    if (
        request.bit_index < 0
        or request.bit_index > 127
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "bit_index must be between "
                "0 and 127."
            )
        )

    # --------------------------------------------------------
    # ANALYSIS
    # --------------------------------------------------------

    try:

        return avalanche_analysis(
            plaintext_bytes,
            key_bytes,
            experiment_type,
            request.bit_index
        )

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

@app.post("/aes/lab/avalanche")
def aes_lab_avalanche(
    request: AESLabExperimentRequest
):

    plaintext_hex = (
        request.plaintext_hex
        .replace(" ", "")
        .strip()
    )

    key_hex = (
        request.key_hex
        .replace(" ", "")
        .strip()
    )

    # --------------------------------------------------------
    # INPUT LENGTH
    # --------------------------------------------------------

    if len(plaintext_hex) != 32:

        raise HTTPException(
            status_code=400,
            detail=(
                "Plaintext must contain exactly "
                "32 hexadecimal characters."
            )
        )

    if len(key_hex) != 32:

        raise HTTPException(
            status_code=400,
            detail=(
                "AES-128 key must contain exactly "
                "32 hexadecimal characters."
            )
        )

    # --------------------------------------------------------
    # HEX CONVERSION
    # --------------------------------------------------------

    try:

        plaintext_bytes = bytes.fromhex(
            plaintext_hex
        )

    except ValueError:

        raise HTTPException(
            status_code=400,
            detail=(
                "Plaintext must contain hexadecimal "
                "characters only."
            )
        )

    try:

        key_bytes = bytes.fromhex(
            key_hex
        )

    except ValueError:

        raise HTTPException(
            status_code=400,
            detail=(
                "Key must contain hexadecimal "
                "characters only."
            )
        )

    # --------------------------------------------------------
    # EXPERIMENT TYPE
    # --------------------------------------------------------

    experiment_type = (
        request.experiment_type
        .strip()
        .lower()
    )

    if experiment_type not in (
        "plaintext",
        "key"
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "experiment_type must be "
                "'plaintext' or 'key'."
            )
        )

    # --------------------------------------------------------
    # BIT RANGE
    # --------------------------------------------------------

    if (
        request.start_bit < 0
        or request.start_bit > 127
        or request.end_bit < 0
        or request.end_bit > 127
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "start_bit and end_bit must "
                "be between 0 and 127."
            )
        )

    if request.start_bit > request.end_bit:

        raise HTTPException(
            status_code=400,
            detail=(
                "start_bit must be less than "
                "or equal to end_bit."
            )
        )

    # --------------------------------------------------------
    # RUN EXPERIMENT
    # --------------------------------------------------------

    try:

        return multi_trial_avalanche_experiment(
            plaintext_bytes,
            key_bytes,
            experiment_type,
            request.start_bit,
            request.end_bit
        )

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

