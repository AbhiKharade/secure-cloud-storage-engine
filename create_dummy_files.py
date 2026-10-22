"""
Utility to generate dummy files (Text, PNG Image, PDF)
for testing the SPPU Cloud Storage CLI (Method 2).
"""

import os
from pathlib import Path


def generate_dummy_files():
    print("Generating dummy test files for Method 2 CLI testing...\n")

    # 1. Text File (~1.5 MB -> 3 blocks of 512 KB)
    txt_path = Path("sample_notes.txt")
    header = (
        "SAVITRIBAI PHULE PUNE UNIVERSITY (SPPU)\n"
        "Department of Computer Engineering - Cloud Computing Laboratory\n"
        "Mini-Project: File Segmentation, AES-256 Encryption & Supabase Storage\n"
        "Testing Dataset: Large Text File for Multi-Block Segmentation Demonstration\n"
        + "=" * 80 + "\n"
    )
    # Generate repeating content to reach ~1.5 MB
    line = "Cloud Security Block Segmentation AES-256 Confidentiality Integrity Data Stream Record.\n"
    content = header + (line * 16500)
    txt_path.write_text(content, encoding="utf-8")
    txt_size = txt_path.stat().st_size
    print(f" [1] Created: {txt_path.name:<22} ({txt_size:,} bytes / {txt_size/1024:.1f} KB / ~{(txt_size/524288):.1f} blocks)")

    # 2. PNG Image (~700 KB -> 2 blocks of 512 KB)
    img_path = Path("sample_image.png")
    # Standard 8-byte PNG signature: 89 50 4E 47 0D 0A 1A 0A
    png_sig = b"\x89PNG\r\n\x1a\n"
    # IHDR chunk (Width: 800, Height: 600, 8-bit depth, Truecolor with alpha)
    ihdr = b"\x00\x00\x00\rIHDR\x00\x00\x03 \x00\x00\x02X\x08\x06\x00\x00\x00\x1a\x91f\x97"
    # Simulated raster payload
    raw_payload = os.urandom(700 * 1024)
    img_path.write_bytes(png_sig + ihdr + raw_payload)
    img_size = img_path.stat().st_size
    print(f" [2] Created: {img_path.name:<22} ({img_size:,} bytes / {img_size/1024:.1f} KB / ~{(img_size/524288):.1f} blocks)")

    # 3. PDF Document (~1.2 MB -> 3 blocks of 512 KB)
    pdf_path = Path("sample_document.pdf")
    pdf_header = (
        b"%PDF-1.4\n"
        b"%\xe2\xe3\xcf\xd3\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources <<>> /MediaBox [0 0 612 792] >>\nendobj\n"
        b"4 0 obj\n<< /Length 1200000 >>\nstream\n"
    )
    pdf_binary_stream = os.urandom(int(1.2 * 1024 * 1024))
    pdf_footer = b"\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \ntrailer\n<< /Root 1 0 R /Size 5 >>\nstartxref\n99\n%%EOF\n"
    pdf_path.write_bytes(pdf_header + pdf_binary_stream + pdf_footer)
    pdf_size = pdf_path.stat().st_size
    print(f" [3] Created: {pdf_path.name:<22} ({pdf_size:,} bytes / {pdf_size/1024:.1f} KB / ~{(pdf_size/524288):.1f} blocks)")

    print("\n[+] All dummy files are ready in your workspace!")
    print("    You can now run 'python main.py upload <filename>' on any of these.\n")


if __name__ == "__main__":
    generate_dummy_files()
