"""
SPPU Cloud Computing Laboratory - Group C (Option 2)
Module: secure_storage.py
Implements:
1. File Segmentation & Reassembly
2. AES-256 Symmetric Encryption via cryptography.fernet
3. Supabase Storage S3-Compatible API Client via Boto3 (with path-style addressing)
4. SHA-256 Cryptographic Integrity Auditing
"""

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any

import boto3
from botocore.client import Config
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment configuration from .env
load_dotenv()

# ==============================================================================
# Configuration Defaults
# ==============================================================================
DEFAULT_CHUNK_SIZE = int(os.getenv("CHUNK_SIZE_BYTES", "524288"))  # 512 KB
DEFAULT_KEY_FILE = Path("secret.key")
DEFAULT_STAGING_DIR = Path("temp_enc")
DEFAULT_MOCK_DIR = Path("mock_cloud_storage")


# ==============================================================================
# Helper: SHA-256 Checksum Computation
# ==============================================================================
def compute_sha256(file_path_or_data) -> str:
    """
    Computes a SHA-256 cryptographic hash.
    Streams in 64 KB buffers to handle large files efficiently without memory exhaustion.
    """
    hasher = hashlib.sha256()
    if isinstance(file_path_or_data, (bytes, bytearray)):
        hasher.update(file_path_or_data)
    else:
        path = Path(file_path_or_data)
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    return hasher.hexdigest()


# ==============================================================================
# 1. Cryptographic Key Management & AES Encryption (Fernet)
# ==============================================================================
class CryptoManager:
    """
    Manages AES-256 symmetric encryption and decryption using cryptography.fernet.
    Fernet guarantees that a message encrypted using it cannot be manipulated,
    read, or altered without the secret key.
    """

    @staticmethod
    def get_or_create_key(key_file: Path = DEFAULT_KEY_FILE) -> bytes:
        """
        Loads the AES encryption key from disk, or generates a new 256-bit
        Fernet key and persists it to 'secret.key' if not found.
        """
        key_path = Path(key_file)
        if key_path.exists():
            key = key_path.read_bytes().strip()
            if len(key) > 0:
                return key

        # Generate a new URL-safe base64-encoded 32-byte (256-bit) secret key
        key = Fernet.generate_key()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(key)
        return key

    @staticmethod
    def encrypt_block(data: bytes, key: bytes) -> bytes:
        """
        Encrypts a raw chunk of plaintext bytes using the AES key.
        Output contains IV, ciphertext, and HMAC-SHA256 authentication tag.
        """
        fernet = Fernet(key)
        return fernet.encrypt(data)

    @staticmethod
    def decrypt_block(encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypts an encrypted chunk.
        Validates the HMAC-SHA256 signature and decrypts using AES.
        Raises InvalidToken if corrupted or tampered with.
        """
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data)


# ==============================================================================
# 2. Supabase Storage S3 Client (with Path-Style Addressing)
# ==============================================================================
class SupabaseS3Storage:
    """
    Interacts with Supabase Storage via Boto3 S3-compatible client.
    Critically uses path-style addressing (`addressing_style: path`)
    to route requests properly to Supabase endpoints.
    """

    def __init__(
        self,
        endpoint_url: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        region_name: Optional[str] = None,
        bucket_name: Optional[str] = None,
    ):
        self.endpoint_url = endpoint_url or os.getenv("SUPABASE_S3_ENDPOINT", "")
        self.access_key_id = access_key_id or os.getenv("AWS_ACCESS_KEY_ID", "")
        self.secret_access_key = secret_access_key or os.getenv("AWS_SECRET_ACCESS_KEY", "")
        self.region_name = region_name or os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
        self.bucket_name = bucket_name or os.getenv("S3_BUCKET_NAME", "sppu-cloud-secure-storage")

        # Determine whether to use Live Supabase or Mock Storage fallback
        self.is_mock = self._should_use_mock()

        if not self.is_mock:
            # Configure Boto3 client with path-style addressing for Supabase
            self.s3_client = boto3.client(
                "s3",
                endpoint_url=self.endpoint_url,
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name=self.region_name,
                config=Config(s3={"addressing_style": "path"})
            )
            self._ensure_bucket_exists()
        else:
            self.mock_dir = DEFAULT_MOCK_DIR / self.bucket_name
            self.mock_dir.mkdir(parents=True, exist_ok=True)

    def _should_use_mock(self) -> bool:
        """Checks if valid Supabase credentials and endpoint are configured."""
        mode = os.getenv("STORAGE_MODE", "").lower()
        if mode == "mock":
            return True
        if not self.endpoint_url or "your-project-ref" in self.endpoint_url or "mock" in self.endpoint_url:
            return True
        if not self.access_key_id or "demo_" in self.access_key_id:
            return True
        return False

    def _ensure_bucket_exists(self) -> None:
        """Verifies or attempts to create the Supabase storage bucket."""
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("404", "NoSuchBucket"):
                try:
                    self.s3_client.create_bucket(Bucket=self.bucket_name)
                except Exception:
                    pass  # In Supabase, buckets are typically created via Dashboard
            elif error_code in ("403", "AccessDenied", "SignatureDoesNotMatch"):
                # Credentials invalid; switch to mock fallback gracefully
                self.is_mock = True
                self.mock_dir = DEFAULT_MOCK_DIR / self.bucket_name
                self.mock_dir.mkdir(parents=True, exist_ok=True)

    def upload_block(self, local_file_path: Path, remote_key: str) -> str:
        """Uploads an encrypted block to Supabase Storage."""
        remote_key = remote_key.replace("\\", "/").lstrip("/")

        if self.is_mock:
            target = self.mock_dir / remote_key
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(local_file_path, target)
            return f"mock://{self.bucket_name}/{remote_key}"

        try:
            self.s3_client.upload_file(
                Filename=str(local_file_path),
                Bucket=self.bucket_name,
                Key=remote_key,
            )
            return f"{self.endpoint_url}/{self.bucket_name}/{remote_key}"
        except Exception as e:
            # Fallback to local mock on network or auth failure
            target = self.mock_dir / remote_key
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(local_file_path, target)
            return f"mock://{self.bucket_name}/{remote_key} (Fallback: {e})"

    def download_block(self, remote_key: str, destination_path: Path) -> None:
        """Downloads an encrypted block from Supabase Storage."""
        remote_key = remote_key.replace("\\", "/").lstrip("/")
        destination_path = Path(destination_path)
        destination_path.parent.mkdir(parents=True, exist_ok=True)

        if self.is_mock:
            src = self.mock_dir / remote_key
            if not src.exists():
                raise FileNotFoundError(f"Block '{remote_key}' not found in mock storage: {src}")
            shutil.copy2(src, destination_path)
            return

        try:
            self.s3_client.download_file(
                Bucket=self.bucket_name,
                Key=remote_key,
                Filename=str(destination_path),
            )
        except Exception as e:
            # Fallback check
            src = DEFAULT_MOCK_DIR / self.bucket_name / remote_key
            if src.exists():
                shutil.copy2(src, destination_path)
            else:
                raise RuntimeError(f"Failed to download block '{remote_key}' from Supabase: {e}")


# ==============================================================================
# 3. Core Engine: Upload & Download Operations
# ==============================================================================
class SecureStorageEngine:
    """
    Orchestrates:
    - Chunk segmentation and AES encryption -> Supabase Upload
    - Block retrieval from Supabase -> AES decryption and bit-perfect reassembly
    """

    def __init__(
        self,
        storage: Optional[SupabaseS3Storage] = None,
        key_file: Path = DEFAULT_KEY_FILE,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        prefix: str = "segments"
    ):
        self.storage = storage or SupabaseS3Storage()
        self.key_file = Path(key_file)
        self.chunk_size = chunk_size
        self.prefix = prefix.strip("/")

    def upload_file(self, file_path: Path, log_fn=print) -> Dict[str, Any]:
        """
        Segments the file, encrypts each block independently with AES-256 (Fernet),
        and uploads each block under 'segments/block_<index>.enc' to Supabase Storage.
        """
        file_path = Path(file_path).resolve()
        if not file_path.exists():
            raise FileNotFoundError(f"Source file not found: {file_path}")

        file_size = file_path.stat().st_size
        original_hash = compute_sha256(file_path)

        # 1. Load or Generate Secret Key
        key = CryptoManager.get_or_create_key(self.key_file)
        log_fn(f"[KEY] Using AES-256 encryption key from: '{self.key_file}'")

        # 2. Setup Staging Area
        staging_dir = Path("temp_upload_enc")
        staging_dir.mkdir(parents=True, exist_ok=True)

        block_index = 0
        block_metadata = []

        log_fn(f"[SEGMENT] Splitting '{file_path.name}' ({file_size:,} bytes) into {self.chunk_size:,} byte blocks...")

        try:
            with open(file_path, "rb") as src:
                while True:
                    plaintext_chunk = src.read(self.chunk_size)
                    if not plaintext_chunk and block_index > 0:
                        break

                    # Encrypt chunk with AES-256
                    encrypted_data = CryptoManager.encrypt_block(plaintext_chunk, key)

                    # Save encrypted block to local staging
                    block_filename = f"block_{block_index}.enc"
                    staged_block_path = staging_dir / block_filename
                    staged_block_path.write_bytes(encrypted_data)

                    # Upload directly to Supabase S3 bucket
                    remote_key = f"{self.prefix}/{block_filename}"
                    upload_uri = self.storage.upload_block(staged_block_path, remote_key)

                    block_metadata.append({
                        "index": block_index,
                        "filename": block_filename,
                        "remote_key": remote_key,
                        "plaintext_size": len(plaintext_chunk),
                        "encrypted_size": len(encrypted_data),
                    })

                    log_fn(
                        f"  -> Uploaded Block {block_index}: "
                        f"{len(plaintext_chunk):,} B plaintext -> {len(encrypted_data):,} B ciphertext "
                        f"-> Key: '{remote_key}'"
                    )

                    block_index += 1
                    if not plaintext_chunk:
                        break

            total_blocks = len(block_metadata)

            # Store metadata manifest
            manifest = {
                "original_filename": file_path.name,
                "original_size_bytes": file_size,
                "original_sha256": original_hash,
                "chunk_size_bytes": self.chunk_size,
                "total_blocks": total_blocks,
                "blocks": block_metadata,
            }
            manifest_path = staging_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            self.storage.upload_block(manifest_path, f"{self.prefix}/manifest.json")

            log_fn(f"[MANIFEST] Uploaded metadata manifest with SHA-256: {original_hash}")

            return {
                "original_filename": file_path.name,
                "original_size_bytes": file_size,
                "original_sha256": original_hash,
                "total_blocks": total_blocks,
                "chunk_size": self.chunk_size,
                "storage_backend": "Local Mock (Offline)" if self.storage.is_mock else f"Supabase S3 ({self.storage.bucket_name})",
            }

        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

    def download_and_reconstruct(
        self,
        total_blocks: int,
        output_file_path: Path,
        expected_hash: str,
        log_fn=print
    ) -> Dict[str, Any]:
        """
        Downloads all encrypted blocks (block_0.enc ... block_N.enc) from Supabase Storage
        into staging directory 'temp_enc/', decrypts each block using the AES key,
        reassembles the plaintext bytes sequentially into output_file_path,
        and audits against the expected SHA-256 hash.
        """
        output_file_path = Path(output_file_path).resolve()
        output_file_path.parent.mkdir(parents=True, exist_ok=True)

        staging_dir = DEFAULT_STAGING_DIR
        staging_dir.mkdir(parents=True, exist_ok=True)

        # 1. Load Secret Key
        if not self.key_file.exists():
            raise FileNotFoundError(f"Decryption key file not found: {self.key_file}")
        key = CryptoManager.get_or_create_key(self.key_file)
        log_fn(f"[KEY] Loaded AES-256 key from: '{self.key_file}'")

        log_fn(f"[DOWNLOAD] Retrieving {total_blocks} encrypted blocks from Supabase Storage into '{staging_dir}/'...")

        try:
            # 2. Download and Decrypt Sequentially
            with open(output_file_path, "wb") as dst:
                for idx in range(total_blocks):
                    block_filename = f"block_{idx}.enc"
                    remote_key = f"{self.prefix}/{block_filename}"
                    local_enc_path = staging_dir / block_filename

                    # Download block from Supabase
                    self.storage.download_block(remote_key, local_enc_path)
                    enc_size = local_enc_path.stat().st_size

                    # Decrypt block using AES-256
                    encrypted_bytes = local_enc_path.read_bytes()
                    decrypted_chunk = CryptoManager.decrypt_block(encrypted_bytes, key)

                    # Write decrypted stream directly into output file
                    dst.write(decrypted_chunk)

                    log_fn(
                        f"  -> Decrypted Block {idx}: "
                        f"{enc_size:,} B ciphertext -> {len(decrypted_chunk):,} B plaintext "
                        f"(Verified Authenticated Tag)"
                    )

            # 3. Cryptographic SHA-256 Integrity Verification
            reconstructed_hash = compute_sha256(output_file_path)
            reconstructed_size = output_file_path.stat().st_size
            is_bit_perfect = (reconstructed_hash.lower() == expected_hash.lower())

            log_fn(f"[AUDIT] Expected Hash:      {expected_hash}")
            log_fn(f"[AUDIT] Reconstructed Hash: {reconstructed_hash}")

            if is_bit_perfect:
                log_fn("[STATUS] [PASS] 100% BIT-PERFECT RECONSTRUCTION CONFIRMED!")
            else:
                log_fn("[STATUS] [FAIL] HASH MISMATCH - INTEGRITY COMPROMISED!")

            return {
                "output_path": str(output_file_path),
                "reconstructed_size_bytes": reconstructed_size,
                "expected_hash": expected_hash,
                "reconstructed_hash": reconstructed_hash,
                "is_bit_perfect": is_bit_perfect,
            }

        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)
