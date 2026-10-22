"""
FastAPI Backend Server for SecureCloud Web Dashboard
SPPU Cloud Computing Laboratory - Group C (Option 2)
Exposes REST APIs for file segmentation, AES-256 encryption, Supabase S3 cloud upload,
and bit-perfect reassembly with cryptographic audit.
"""

import hashlib
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from secure_storage import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_KEY_FILE,
    CryptoManager,
    SecureStorageEngine,
    SupabaseS3Storage,
    compute_sha256,
)

# Initialize FastAPI App
app = FastAPI(
    title="SecureCloud - SPPU Cloud Computing",
    description="File Segmentation, AES-256 Encryption & Supabase S3 Storage Engine",
    version="2.0.0",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Workspace directories
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOADS_TEMP_DIR = BASE_DIR / "web_temp"
RECONSTRUCTED_DIR = BASE_DIR / "web_reconstructed"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_TEMP_DIR.mkdir(parents=True, exist_ok=True)
RECONSTRUCTED_DIR.mkdir(parents=True, exist_ok=True)

# In-memory session catalog for UI convenience
UPLOAD_CATALOG: List[Dict[str, Any]] = []


class DownloadRequest(BaseModel):
    file_id: str
    total_blocks: int
    expected_hash: str
    original_filename: Optional[str] = "restored_file"


@app.get("/api/status")
def get_system_status():
    """Returns the current cloud storage and cryptographic subsystem status."""
    storage = SupabaseS3Storage()
    key_exists = DEFAULT_KEY_FILE.exists()
    return {
        "status": "online",
        "storage_mode": "mock" if storage.is_mock else "supabase",
        "backend_label": "Local Mock Storage (Offline Mode)" if storage.is_mock else "Supabase S3 Cloud Gateway",
        "bucket_name": storage.bucket_name,
        "region": storage.region_name,
        "endpoint": storage.endpoint_url if not storage.is_mock else "mock://local",
        "key_present": key_exists,
        "default_chunk_size": DEFAULT_CHUNK_SIZE,
    }


@app.post("/api/upload")
async def upload_and_encrypt(
    file: UploadFile = File(...),
    chunk_size: int = Form(DEFAULT_CHUNK_SIZE),
):
    """
    Receives an arbitrary file, computes SHA-256, segments into blocks,
    encrypts each block with AES-256 (Fernet), uploads to Supabase S3,
    and returns detailed block telemetry for the visualization UI.
    """
    file_id = f"vault_{uuid.uuid4().hex[:8]}"
    temp_file_path = UPLOADS_TEMP_DIR / f"{file_id}_{file.filename}"

    try:
        # Save uploaded stream to disk
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        file_size = temp_file_path.stat().st_size
        original_hash = compute_sha256(temp_file_path)

        storage = SupabaseS3Storage()
        prefix = f"segments/{file_id}"
        engine = SecureStorageEngine(
            storage=storage,
            chunk_size=chunk_size,
            prefix=prefix,
        )

        # Execute upload workflow
        key = CryptoManager.get_or_create_key(DEFAULT_KEY_FILE)
        staging_dir = Path(tempfile.mkdtemp(prefix="web_upload_"))

        blocks_summary = []
        block_idx = 0

        with open(temp_file_path, "rb") as src:
            while True:
                chunk = src.read(chunk_size)
                if not chunk and block_idx > 0:
                    break

                pt_size = len(chunk)
                encrypted = CryptoManager.encrypt_block(chunk, key)
                ct_size = len(encrypted)

                block_name = f"block_{block_idx}.enc"
                staged_path = staging_dir / block_name
                staged_path.write_bytes(encrypted)

                remote_key = f"{prefix}/{block_name}"
                upload_uri = storage.upload_block(staged_path, remote_key)

                # Ciphertext sample for security inspection
                cipher_sample = encrypted[:64].decode("latin-1", errors="replace") + "..."

                blocks_summary.append({
                    "index": block_idx,
                    "filename": block_name,
                    "remote_key": remote_key,
                    "plaintext_size": pt_size,
                    "encrypted_size": ct_size,
                    "cipher_preview": cipher_sample,
                    "uri": upload_uri,
                })

                block_idx += 1
                if not chunk:
                    break

        shutil.rmtree(staging_dir, ignore_errors=True)

        catalog_entry = {
            "file_id": file_id,
            "filename": file.filename,
            "original_size": file_size,
            "original_sha256": original_hash,
            "total_blocks": len(blocks_summary),
            "chunk_size": chunk_size,
            "prefix": prefix,
            "blocks": blocks_summary,
            "backend": "Mock Storage" if storage.is_mock else f"Supabase S3 ({storage.bucket_name})",
        }
        UPLOAD_CATALOG.insert(0, catalog_entry)

        return {
            "success": True,
            "data": catalog_entry,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if temp_file_path.exists():
            temp_file_path.unlink()


@app.post("/api/download")
async def download_and_reassemble(req: DownloadRequest):
    """
    Downloads encrypted blocks from Supabase, decrypts with AES-256,
    reassembles the restored file, and performs SHA-256 integrity audit.
    """
    storage = SupabaseS3Storage()
    prefix = f"segments/{req.file_id}"
    engine = SecureStorageEngine(
        storage=storage,
        prefix=prefix,
    )

    restored_filename = f"restored_{req.original_filename}"
    output_path = RECONSTRUCTED_DIR / f"{req.file_id}_{restored_filename}"

    try:
        result = engine.download_and_reconstruct(
            total_blocks=req.total_blocks,
            output_file_path=output_path,
            expected_hash=req.expected_hash,
        )

        return {
            "success": True,
            "file_id": req.file_id,
            "filename": restored_filename,
            "download_url": f"/api/get-file/{output_path.name}",
            "reconstructed_size": result["reconstructed_size_bytes"],
            "expected_hash": result["expected_hash"],
            "reconstructed_hash": result["reconstructed_hash"],
            "is_bit_perfect": result["is_bit_perfect"],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Reassembly failed: {str(e)}")


@app.get("/api/get-file/{filename}")
async def get_restored_file(filename: str):
    """Serves the reconstructed file as a direct browser download."""
    target_path = RECONSTRUCTED_DIR / filename
    if not target_path.exists():
        raise HTTPException(status_code=404, detail="Requested file not found")
    
    original_display_name = filename.split("_", 2)[-1] if "_" in filename else filename
    return FileResponse(
        path=target_path,
        filename=original_display_name,
        media_type="application/octet-stream",
    )


@app.get("/api/catalog")
def get_catalog():
    """Returns the list of uploaded files during this session."""
    return UPLOAD_CATALOG


# Mount static assets directory
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serves the main single-page web dashboard."""
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>Loading SecureCloud UI...</h1>")
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))


if __name__ == "__main__":
    import uvicorn
    print("\n" + "=" * 70)
    print("   SPPU Cloud Computing: Secure Cloud Storage Dashboard")
    print("   Starting Local Web Server at: http://localhost:8000")
    print("=" * 70 + "\n")
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
