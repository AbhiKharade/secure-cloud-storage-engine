#!/usr/bin/env python3
"""
SPPU Cloud Computing Laboratory - Group C (Option 2)
End-to-End Automated Demonstration Script
Demonstrates:
1. Generation of diverse test files (Text, Image, PDF).
2. 512 KB block segmentation & AES-256 (Fernet) block-level encryption.
3. Supabase S3 / Mock Storage upload under 'segments/block_<index>.enc'.
4. Download of encrypted blocks to 'temp_enc/', AES decryption & bit-perfect stitching.
5. SHA-256 cryptographic integrity validation comparing original vs reconstructed files.
6. Deliberate tamper injection to prove rejection of compromised cloud ciphertext.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from secure_storage import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_KEY_FILE,
    CryptoManager,
    SecureStorageEngine,
    SupabaseS3Storage,
    compute_sha256,
)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


def print_step(title: str):
    if RICH_AVAILABLE:
        console.print(f"\n[bold yellow]>>> {title}[/bold yellow]")
    else:
        print(f"\n>>> {title}")


def main():
    demo_dir = Path("demo_files").resolve()
    shutil.rmtree(demo_dir, ignore_errors=True)
    demo_dir.mkdir(parents=True, exist_ok=True)

    if RICH_AVAILABLE:
        console.print(Panel.fit(
            "[bold cyan]SPPU CLOUD COMPUTING LABORATORY MINI-PROJECT (GROUP C, OPTION 2)[/bold cyan]\n"
            "[green]File Segmentation, AES-256 Encryption & Supabase Storage (S3-Compatible API)[/green]",
            border_style="cyan"
        ))
    else:
        print("=" * 72)
        print("   SPPU CLOUD COMPUTING LABORATORY MINI-PROJECT (GROUP C, OPTION 2)")
        print("=" * 72)

    # --------------------------------------------------------------------------
    # Step 1: Create Sample Files (Text, Image, PDF)
    # --------------------------------------------------------------------------
    print_step("STEP 1: Generating Sample Datasets (Text, Image, PDF)")

    # 1a. Text File
    txt_file = demo_dir / "cloud_computing_report.txt"
    txt_content = (
        "Savitribai Phule Pune University (SPPU)\n"
        "Group C, Option 2: Cloud Storage Security Mini-Project\n"
        "File Segmentation, AES-256 Block Encryption, Supabase Storage Integration\n"
        "Integrity Protocol: SHA-256 Bit-Level Verification\n"
        + ("Confidential Cloud Block Stream Data Line\n" * 1500)
    )
    txt_file.write_text(txt_content, encoding="utf-8")
    print(f" [+] Generated Text File:  {txt_file.name} ({txt_file.stat().st_size:,} bytes)")

    # 1b. Simulated PNG Image
    img_file = demo_dir / "satellite_scan.png"
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06\x00\x00\x00"
    img_data = png_header + os.urandom(600 * 1024)  # ~600 KB -> 2 chunks (512KB + remaining)
    img_file.write_bytes(img_data)
    print(f" [+] Generated PNG Image:  {img_file.name} ({img_file.stat().st_size:,} bytes)")

    # 1c. Simulated PDF Document (~1.2 MB -> 3 chunks)
    pdf_file = demo_dir / "cloud_architecture.pdf"
    pdf_data = b"%PDF-1.4\n%SPPU Research Document\n" + os.urandom(int(1.2 * 1024 * 1024))
    pdf_file.write_bytes(pdf_data)
    print(f" [+] Generated PDF File:   {pdf_file.name} ({pdf_file.stat().st_size:,} bytes)")

    # --------------------------------------------------------------------------
    # Step 2: Initialize Supabase Storage Client
    # --------------------------------------------------------------------------
    storage = SupabaseS3Storage()
    backend_name = "Local Mock Storage (Offline Mode)" if storage.is_mock else f"Supabase S3 ({storage.bucket_name})"
    print(f"\n [i] Active Cloud Backend: {backend_name}")

    engine = SecureStorageEngine(
        storage=storage,
        chunk_size=DEFAULT_CHUNK_SIZE,  # 512 KB
    )

    test_files = [txt_file, img_file, pdf_file]
    results = []

    # --------------------------------------------------------------------------
    # Step 3: Execute Upload & Download for Each Dataset
    # --------------------------------------------------------------------------
    for sample in test_files:
        print_step(f"PROCESSING: '{sample.name}' ({sample.stat().st_size:,} bytes)")

        # Upload
        print(" [1] Segmenting & Encrypting with AES-256 (Fernet)...")
        up_res = engine.upload_file(sample, log_fn=lambda m: print(f"     {m}"))

        # Reconstruct
        restored_file = demo_dir / f"restored_{sample.name}"
        print(f"\n [2] Downloading {up_res['total_blocks']} encrypted blocks and Reconstructing...")
        down_res = engine.download_and_reconstruct(
            total_blocks=up_res["total_blocks"],
            output_file_path=restored_file,
            expected_hash=up_res["original_sha256"],
            log_fn=lambda m: print(f"     {m}")
        )

        results.append({
            "name": sample.name,
            "original_size": f"{up_res['original_size_bytes']:,} B",
            "blocks": up_res["total_blocks"],
            "original_sha": up_res["original_sha256"][:16] + "...",
            "restored_sha": down_res["reconstructed_hash"][:16] + "...",
            "status": "PASS (100% Match)" if down_res["is_bit_perfect"] else "FAIL",
        })

    # --------------------------------------------------------------------------
    # Step 4: Security Resilience Test - Tampering Detection
    # --------------------------------------------------------------------------
    print_step("SECURITY AUDIT: Testing Ciphertext Tamper Detection")
    print(" [i] Corrupting 1 byte of block_0.enc in storage to test cryptographic rejection...")
    
    # Target block in mock or local directory
    target_block = Path("mock_cloud_storage") / storage.bucket_name / "segments" / "block_0.enc"
    if target_block.exists():
        raw_cipher = bytearray(target_block.read_bytes())
        raw_cipher[15] ^= 0xFF  # Flip bit
        target_block.write_bytes(raw_cipher)

        try:
            tamper_dest = demo_dir / "tampered_output.bin"
            engine.download_and_reconstruct(
                total_blocks=1,
                output_file_path=tamper_dest,
                expected_hash="invalid",
                log_fn=lambda m: None
            )
            print(" [x] Error: Tampered ciphertext was decrypted without raising error!")
        except Exception as ex:
            print(f" [PASS] Cryptographic Security Confirmed: Fernet rejected tampered block:\n        -> {ex}")

    # --------------------------------------------------------------------------
    # Step 5: Final Evaluation Table
    # --------------------------------------------------------------------------
    print_step("FINAL SPPU MINI-PROJECT EVALUATION REPORT")
    if RICH_AVAILABLE:
        table = Table(title="Bit-Perfect Verification Matrix", show_header=True, header_style="bold magenta")
        table.add_column("Dataset Filename", style="bold")
        table.add_column("Size", justify="right")
        table.add_column("Blocks", justify="center")
        table.add_column("Original SHA-256")
        table.add_column("Restored SHA-256")
        table.add_column("Integrity Audit", style="bold green")

        for r in results:
            table.add_row(
                r["name"],
                r["original_size"],
                str(r["blocks"]),
                r["original_sha"],
                r["restored_sha"],
                r["status"],
            )
        console.print(table)
    else:
        for r in results:
            print(f" {r['name']} | Size: {r['original_size']} | Blocks: {r['blocks']} | Result: {r['status']}")

    print("\n[+] Demonstration complete! Ready for external viva examination.\n")


if __name__ == "__main__":
    main()
