"""Resource limits and file-type tables for attachment scanning.

Central, hard-coded safety envelope for ATTACH-SCAN phases. Every scanner
level (basic validation, archive inspection, static analysis, sandboxing)
must enforce these caps so no attachment can exhaust worker memory, disk,
or CPU regardless of how hostile the payload is.
"""

# ---------------------------------------------------------------------------
# Size limits (bytes)
# ---------------------------------------------------------------------------

# Largest single attachment accepted for scanning (25 MB, Gmail's own cap).
MAX_ATTACHMENT_SIZE_BYTES = 25_000_000

# Largest number of attachments considered per email.
MAX_ATTACHMENTS_PER_EMAIL = 10

# Archive inspection (Phase 2): max nesting depth (zip-in-zip-in-zip ...).
MAX_ARCHIVE_DEPTH = 3

# Archive inspection (Phase 2): max files extracted from one archive.
MAX_EXTRACTED_FILES = 50

# Archive inspection (Phase 2): max total uncompressed bytes extracted.
MAX_EXTRACTED_TOTAL_SIZE = 50_000_000

# Archive inspection (Phase 2): uncompressed/compressed ratio above which an
# archive is treated as a suspected zip bomb and not extracted.
MAX_ARCHIVE_COMPRESSION_RATIO = 200

# Content analysis (Phase 3): PDF page-processing cap and per-attachment URL cap.
MAX_PAGES_IN_PDF = 100
MAX_URLS_PER_ATTACHMENT = 50

# Content analysis (Phase 3): text-extraction cap (chars) before analysis.
MAX_TEXT_EXTRACT_CHARS = 200_000

# Streaming chunk size for downloads and hashing (64 KB).
STREAM_CHUNK_SIZE = 65_536

# Worker RSS above which scanning is aborted (memory-safety kill switch).
MEMORY_CRITICAL_THRESHOLD_MB = 1000

# ---------------------------------------------------------------------------
# Supported MIME types
# ---------------------------------------------------------------------------

SUPPORTED_MIME_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/zip",
    "application/x-rar-compressed",
    "application/vnd.rar",
    "application/x-7z-compressed",
    "application/x-tar",
    "application/gzip",
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
    "text/html",
    "text/plain",
    # Executables are deliberately scannable (Phase 2 malware detection):
    # skipping them would let MZ payloads evade inspection entirely.
    "application/x-msdownload",
    "application/x-executable",
}

# ---------------------------------------------------------------------------
# Magic signatures: file-header byte prefixes mapped to MIME types.
# Used for content-based type detection (declared MIME headers are attacker
# controlled and routinely spoofed).
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES = {
    b"%PDF": "application/pdf",
    b"PK\x03\x04": "application/zip",
    b"PK\x05\x06": "application/zip",  # empty zip
    b"PK\x07\x08": "application/zip",  # spanned zip
    b"MZ": "application/x-msdownload",  # Windows PE executable
    b"\x1f\x8b": "application/gzip",
    b"7z\xbc\xaf\x27\x1c": "application/x-7z-compressed",
    b"Rar!\x1a\x07": "application/x-rar-compressed",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "application/vnd.ms-office",  # OLE2 (doc/xls/ppt)
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"ustar": "application/x-tar",
}

# WEBP is RIFF-container based: "RIFF" at offset 0 and "WEBP" at offset 8.
WEBP_RIFF_MAGIC = b"RIFF"
WEBP_FORMAT_MAGIC = b"WEBP"

# Longest signatures first so specific prefixes win over short ones
# (e.g. RIFF/WebP vs. generic matches) when scanning raw headers.
_SORTED_MAGIC_SIGNATURES = sorted(MAGIC_SIGNATURES.items(), key=lambda kv: len(kv[0]), reverse=True)

# ---------------------------------------------------------------------------
# Executable extensions — always treated as high risk regardless of the
# declared MIME type.
# ---------------------------------------------------------------------------

EXECUTABLE_EXTENSIONS = {
    ".exe", ".com", ".bat", ".cmd", ".scr", ".pif", ".cpl", ".msi", ".msp",
    ".dll", ".sys", ".drv", ".jar", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".ps1", ".psm1", ".sh", ".bash", ".app", ".deb", ".rpm", ".apk",
    ".hta", ".lnk", ".reg",
}


def is_executable_extension(filename: str) -> bool:
    """Return True if the filename carries a known executable extension."""
    from pathlib import PurePosixPath

    return PurePosixPath(filename or "").suffix.lower() in EXECUTABLE_EXTENSIONS
