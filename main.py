#!/usr/bin/env python3
"""
SPPU Cloud Computing Laboratory - Group C (Option 2)
Main CLI Interface
File Segmentation, AES-256 (Fernet) Encryption, Supabase Storage S3 Integration,
and Bit-Perfect Reassembly with Cryptographic Integrity Audit.

Usage:
  Upload:
    python main.py upload <file_path> [--chunk-size 524288] [--key-file secret.key]

  Download & Verify:
    python main.py download <total_blocks> <output_file_path> <expected_hash> [--key-file secret.key]
"""

import argparse
import sys
from pathlib import Path

from secure_storage import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_KEY_FILE,
    SecureStorageEngine,
    SupabaseS3Storage,
)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


def print_banner():
    banner = (
        "[bold cyan]========================================================================\n"
        "   SAVITRIBAI PHULE PUNE UNIVERSITY (SPPU)\n"
        "   Department of Computer Engineering - Cloud Computing Laboratory\n"
        "   Mini-Project: File Segmentation, AES-256 & Supabase S3 Integration\n"
        "========================================================================[/bold cyan]"
    )
    if RICH_AVAILABLE:
        console.print(banner)
    else:
        print("=" * 72)
        print("   SAVITRIBAI PHULE PUNE UNIVERSITY (SPPU)")
        print("   Mini-Project: File Segmentation, AES-256 & Supabase S3 Integration")
        print("=" * 72)


def log_message(msg: str):
    if RICH_AVAILABLE:
        console.print(msg)
    else:
        print(msg)


def handle_upload(args):
    print_banner()
    source_file = Path(args.file_path)
    if not source_file.exists():
        log_message(f"[bold red]Error: Source file '{source_file}' does not exist.[/bold red]")
        sys.exit(1)

    key_file = Path(args.key_file)
    chunk_size = args.chunk_size

    # Initialize Engine
    storage = SupabaseS3Storage()
    engine = SecureStorageEngine(
        storage=storage,
        key_file=key_file,
        chunk_size=chunk_size,
    )

    log_message(f"[bold green]Starting Upload Pipeline for: '{source_file.name}'[/bold green]")
    log_message(f"Storage Mode: [bold yellow]{'Local Mock Cloud' if storage.is_mock else 'Supabase S3 Cloud'}[/bold yellow]")
    log_message(f"Target Bucket: '{storage.bucket_name}'\n")

    try:
        summary = engine.upload_file(source_file, log_fn=log_message)

        if RICH_AVAILABLE:
            table = Table(title="Upload & Block Segmentation Summary", show_header=True, header_style="bold magenta")
            table.add_column("Parameter", style="dim", width=25)
            table.add_column("Value")

            table.add_row("Original File", summary["original_filename"])
            table.add_row("Original Size", f"{summary['original_size_bytes']:,} bytes ({summary['original_size_bytes']/1024:.2f} KB)")
            table.add_row("Original SHA-256", f"[bold green]{summary['original_sha256']}[/bold green]")
            table.add_row("Total Blocks Uploaded", f"[bold cyan]{summary['total_blocks']}[/bold cyan]")
            table.add_row("Block Chunk Size", f"{summary['chunk_size']:,} bytes ({summary['chunk_size']/1024:.0f} KB)")
            table.add_row("Cloud Backend", summary["storage_backend"])
            table.add_row("Encryption Key File", str(key_file.resolve()))

            console.print("\n")
            console.print(table)
            console.print("\n[bold green]To download and reconstruct this file, run:[/bold green]")
            console.print(
                f"[bold yellow]python main.py download {summary['total_blocks']} "
                f"./restored_{summary['original_filename']} {summary['original_sha256']}[/bold yellow]\n"
            )
        else:
            print("\n--- UPLOAD & SEGMENTATION SUMMARY ---")
            print(f"File Name:        {summary['original_filename']}")
            print(f"Size:             {summary['original_size_bytes']} bytes")
            print(f"SHA-256 Hash:     {summary['original_sha256']}")
            print(f"Total Blocks:     {summary['total_blocks']}")
            print(f"Storage Target:   {summary['storage_backend']}")
            print(f"Secret Key File:  {key_file.resolve()}")
            print(f"\nDownload command:\npython main.py download {summary['total_blocks']} ./restored_{summary['original_filename']} {summary['original_sha256']}\n")

    except Exception as ex:
        log_message(f"[bold red]Upload failed: {ex}[/bold red]")
        sys.exit(1)


def handle_download(args):
    print_banner()
    output_path = Path(args.output_file_path)
    total_blocks = args.total_blocks
    expected_hash = args.expected_hash.strip().lower()
    key_file = Path(args.key_file)

    storage = SupabaseS3Storage()
    engine = SecureStorageEngine(
        storage=storage,
        key_file=key_file,
    )

    log_message(f"[bold green]Starting Download & Reassembly Pipeline[/bold green]")
    log_message(f"Retrieving {total_blocks} blocks from '{storage.bucket_name}' into target: '{output_path}'\n")

    try:
        result = engine.download_and_reconstruct(
            total_blocks=total_blocks,
            output_file_path=output_path,
            expected_hash=expected_hash,
            log_fn=log_message,
        )

        if RICH_AVAILABLE:
            table = Table(title="Reassembly & Cryptographic Audit", show_header=True, header_style="bold cyan")
            table.add_column("Integrity Metric", width=25)
            table.add_column("Verification Result")

            table.add_row("Restored File Path", result["output_path"])
            table.add_row("Reassembled Size", f"{result['reconstructed_size_bytes']:,} bytes")
            table.add_row("Expected SHA-256", result["expected_hash"])
            table.add_row("Computed SHA-256", result["reconstructed_hash"])

            if result["is_bit_perfect"]:
                table.add_row("Cryptographic Audit", "[bold green]PASS (100% Bit-Perfect Match)[/bold green]")
            else:
                table.add_row("Cryptographic Audit", "[bold red]FAIL (Hash Mismatch)[/bold red]")

            console.print("\n")
            console.print(table)
            console.print("\n")
        else:
            print("\n--- REASSEMBLY & INTEGRITY REPORT ---")
            print(f"Restored Path:    {result['output_path']}")
            print(f"Expected Hash:    {result['expected_hash']}")
            print(f"Reconstructed:    {result['reconstructed_hash']}")
            print(f"Audit Status:     {'PASS (Bit-Perfect)' if result['is_bit_perfect'] else 'FAIL'}\n")

        if not result["is_bit_perfect"]:
            sys.exit(1)

    except Exception as ex:
        log_message(f"[bold red]Reassembly failed: {ex}[/bold red]")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="sppu_secure_cloud",
        description="SPPU Cloud Computing Laboratory: File Segmentation, AES-256 & Supabase S3 Integration",
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Sub-commands")

    # Upload command: python main.py upload <file_path>
    up_parser = subparsers.add_parser("upload", help="Segment file, encrypt with AES-256, and upload to Supabase")
    up_parser.add_argument("file_path", help="Path of the file to encrypt and upload (PDF, image, text, or binary)")
    up_parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"Block size in bytes (default: {DEFAULT_CHUNK_SIZE} = 512 KB)",
    )
    up_parser.add_argument(
        "--key-file",
        default=str(DEFAULT_KEY_FILE),
        help=f"Path to secret key file (default: '{DEFAULT_KEY_FILE}')",
    )
    up_parser.set_defaults(func=handle_upload)

    # Download command: python main.py download <total_blocks> <output_file_path> <expected_hash>
    down_parser = subparsers.add_parser(
        "download",
        help="Download encrypted blocks from Supabase, decrypt with AES, reassemble, and verify SHA-256",
    )
    down_parser.add_argument("total_blocks", type=int, help="Total number of blocks to retrieve")
    down_parser.add_argument("output_file_path", help="Destination path for reconstructed file")
    down_parser.add_argument("expected_hash", help="Expected original SHA-256 hex digest for integrity audit")
    down_parser.add_argument(
        "--key-file",
        default=str(DEFAULT_KEY_FILE),
        help=f"Path to secret key file (default: '{DEFAULT_KEY_FILE}')",
    )
    down_parser.set_defaults(func=handle_download)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
