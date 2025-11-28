"""File hashing utilities for integrity monitoring"""
import hashlib
import json
import os
from typing import Dict, Optional


def hash_content(file_path: str) -> Optional[str]:
    """Calculate SHA-256 hash of file content"""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def get_file_metadata(file_path: str) -> Optional[Dict]:
    """Get file metadata (size, mtime, ctime, permissions)"""
    try:
        s = os.stat(file_path, follow_symlinks=False)
        return {
            "size": s.st_size,
            "mtime": int(s.st_mtime),
            "ctime": int(s.st_ctime),
            "mode": s.st_mode,
            "readonly": not os.access(file_path, os.W_OK),
        }
    except (PermissionError, FileNotFoundError, OSError):
        return None


def calculate_state_hash(file_path: str) -> Optional[Dict]:
    """Calculate complete state hash including content and metadata"""
    if not os.path.exists(file_path) or os.path.isdir(file_path):
        return None
    
    metadata = get_file_metadata(file_path)
    content_hash = hash_content(file_path)
    
    if metadata is None or content_hash is None:
        return None
    
    state_obj = {
        "path": os.path.abspath(file_path),
        "content_hash": content_hash,
        "metadata": metadata,
    }
    
    state_bytes = json.dumps(state_obj, sort_keys=True, separators=(",", ":")).encode()
    state_hash = hashlib.sha256(state_bytes).hexdigest()
    
    return {
        "path": state_obj["path"],
        "content_hash": content_hash,
        "metadata": metadata,
        "state_hash": state_hash,
        "file_size": metadata["size"]
    }


def is_temp_file(file_path: str) -> bool:
    """Check if file should be ignored (temp files, editor backups, etc.)"""
    filename = os.path.basename(file_path)
    ignore_patterns = [
        filename.endswith("~"),
        filename.endswith(".swp"),
        filename.endswith(".tmp"),
        filename.startswith("."),
        filename.endswith(".pyc"),
        "__pycache__" in file_path,
        ".git" in file_path,
    ]
    return any(ignore_patterns)
