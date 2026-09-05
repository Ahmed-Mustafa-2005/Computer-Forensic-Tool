"""
forensic_backend.py

Business logic for the Disk & Registry Forensic Analysis Tool.

Deliberately contains NO GUI code — every function here takes plain
arguments and returns plain data structures (dicts / lists / strings),
so it can be driven from the Tkinter GUI, a CLI, or a test suite.

Windows-only: relies on `winreg` and `ctypes.windll`, and on `pytsk3`
(The Sleuth Kit bindings) for real filesystem parsing of disk images.
"""

import os
import re
import sys
import json
import time
import html
import hashlib
import logging
import ctypes
import mimetypes
from datetime import datetime, timezone

try:
    import winreg
except ImportError:  # allows import on non-Windows for linting/testing
    winreg = None

try:
    import pytsk3
except ImportError:
    pytsk3 = None

try:
    import pyewf
except ImportError:
    pyewf = None


# ---------------------------------------------------------------------------
# Logging — full tracebacks go here; the GUI only ever shows a short message
# ---------------------------------------------------------------------------
LOG_DIR = os.path.join(os.path.expanduser("~"), "ForensicToolLogs")
os.makedirs(LOG_DIR, exist_ok=True)
DEBUG_LOG_PATH = os.path.join(LOG_DIR, "debug.log")

logging.basicConfig(
    filename=DEBUG_LOG_PATH,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("forensic_tool")

TOOL_NAME = "Disk & Registry Forensic Analysis Tool"
TOOL_VERSION = "2.0"


class OperationCancelled(Exception):
    """Raised internally when the user cancels a running background job."""


def _check_cancelled(cancel_event, message="Operation cancelled by user."):
    if cancel_event is not None and cancel_event.is_set():
        raise OperationCancelled(message)


# ---------------------------------------------------------------------------
# Chain of custody
# ---------------------------------------------------------------------------
class ChainOfCustody:
    """
    Append-only, timestamped log of every action taken during a session.
    Flushed to disk after every entry so a crash doesn't lose the record.
    """

    def __init__(self, examiner, case_number, log_path=None):
        self.examiner = examiner
        self.case_number = case_number
        self.log_path = log_path or os.path.join(
            LOG_DIR, f"chain_of_custody_{case_number}_{int(time.time())}.json"
        )
        self.entries = []
        self.log_event(
            "SESSION_START",
            f"Examiner '{examiner}' started session for case '{case_number}'",
        )

    def log_event(self, action, description, extra=None):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "examiner": self.examiner,
            "case_number": self.case_number,
            "action": action,
            "description": description,
        }
        if extra:
            entry["extra"] = extra
        self.entries.append(entry)
        self._flush()
        logger.info("COC: %s - %s", action, description)
        return entry

    def _flush(self):
        try:
            with open(self.log_path, "w") as f:
                json.dump(self.entries, f, indent=2)
        except Exception:
            logger.exception("Failed to write chain-of-custody log")

    def as_text(self):
        lines = [
            f"Chain of Custody — Case {self.case_number} — Examiner {self.examiner}",
            "=" * 60,
        ]
        for e in self.entries:
            lines.append(f"[{e['timestamp']}] {e['action']}: {e['description']}")
            if "extra" in e:
                lines.append(f"    {e['extra']}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------
def hash_file(path, algos=("md5", "sha256"), chunk_size=4 * 1024 * 1024, progress_cb=None, cancel_event=None):
    """Stream-hash a file with one or more algorithms without loading it into memory."""
    hashers = {algo: hashlib.new(algo) for algo in algos}
    total = os.path.getsize(path)
    read = 0
    with open(path, "rb") as f:
        while True:
            _check_cancelled(cancel_event, "Hashing cancelled by user.")
            chunk = f.read(chunk_size)
            if not chunk:
                break
            for h in hashers.values():
                h.update(chunk)
            read += len(chunk)
            if progress_cb:
                progress_cb(read, total)
    return {algo: h.hexdigest() for algo, h in hashers.items()}


def calculate_file_hash(path, expected_hash=None, coc=None, progress_cb=None, cancel_event=None):
    """Calculate hashes and optionally compare one against a reference value."""
    if not os.path.isfile(path):
        return None, f"File does not exist or is not a regular file: {path}"
    try:
        hashes = hash_file(
            path,
            algos=("md5", "sha1", "sha256"),
            progress_cb=progress_cb,
            cancel_event=cancel_event,
        )
        result = {"file": os.path.abspath(path), "algorithms": hashes, "integrity": {"status": "NOT_CHECKED"}}
        if expected_hash and expected_hash.strip():
            reference = expected_hash.strip().lower()
            algorithm_by_length = {32: "md5", 40: "sha1", 64: "sha256"}
            algorithm = algorithm_by_length.get(len(reference))
            if not algorithm or any(character not in "0123456789abcdef" for character in reference):
                return None, "Reference hash must be a valid MD5, SHA-1, or SHA-256 hexadecimal value."
            result["integrity"] = {
                "status": "MATCH" if hashes[algorithm] == reference else "MISMATCH",
                "algorithm": algorithm,
                "reference": reference,
                "calculated": hashes[algorithm],
            }
        if coc:
            coc.log_event("HASH_CALCULATED", f"Calculated hashes for {path}", extra=result)
        return result, None
    except OperationCancelled:
        raise
    except Exception as e:
        logger.exception("Error calculating file hashes")
        return None, f"An error occurred while calculating hashes: {e}"


def verify_file_hash(path, expected_hash, coc=None, progress_cb=None, cancel_event=None):
    """
    Re-hash a file and compare it against a previously recorded hash — the
    standard "does this image still match what we acquired" check, usable
    independently of a full analysis run (e.g. weeks later, on request).
    Auto-detects the algorithm from the expected hash's length.
    """
    expected_hash = (expected_hash or "").strip().lower()
    algo_by_len = {32: "md5", 40: "sha1", 64: "sha256"}
    algo = algo_by_len.get(len(expected_hash))
    if not algo:
        return None, "Expected hash must be a 32-char MD5, 40-char SHA1, or 64-char SHA256 hex value."

    try:
        actual = hash_file(path, algos=(algo,), progress_cb=progress_cb, cancel_event=cancel_event)[algo]
    except OperationCancelled:
        raise
    except Exception as e:
        logger.exception("Error verifying hash")
        return None, f"An error occurred while hashing the file: {e}"

    match = actual == expected_hash
    result = {"file": os.path.basename(path), "algorithm": algo, "expected": expected_hash,
              "actual": actual, "match": match}

    if coc:
        coc.log_event(
            "HASH_VERIFICATION",
            f"Verified {os.path.basename(path)} against a provided {algo.upper()} hash: "
            f"{'MATCH' if match else 'MISMATCH'}",
            extra=result,
        )

    return result, None


def analyze_file_metadata(path, coc=None, progress_cb=None, cancel_event=None):
    """Collect read-only filesystem metadata for any regular evidence file."""
    if not os.path.isfile(path):
        return None, f"Evidence path is not a regular file: {path}"

    try:
        stat_info = os.stat(path)
        result = {
            "file_name": os.path.basename(path),
            "file_path": os.path.abspath(path),
            "file_extension": os.path.splitext(path)[1].lower() or "(none)",
            "mime_type": mimetypes.guess_type(path)[0] or "application/octet-stream",
            "file_size": stat_info.st_size,
            "created_utc": datetime.fromtimestamp(stat_info.st_ctime, timezone.utc).isoformat(),
            "modified_utc": datetime.fromtimestamp(stat_info.st_mtime, timezone.utc).isoformat(),
            "accessed_utc": datetime.fromtimestamp(stat_info.st_atime, timezone.utc).isoformat(),
        }
        if coc:
            coc.log_event("FILE_METADATA_READ", f"Read metadata for {path}", extra=result)
        return result, None
    except OperationCancelled:
        raise
    except Exception as e:
        logger.exception("Error reading file metadata")
        return None, f"An error occurred while reading file metadata: {e}"


# ---------------------------------------------------------------------------
# Split-image combination
# ---------------------------------------------------------------------------
SEGMENT_RE = re.compile(r"\.(\d{3,})$")


def find_split_segments(image_dir):
    """
    Find split raw/dd image segments (.001, .002, .003, ...) in a directory
    and return them sorted numerically (NOT alphabetically — alphabetical
    sort breaks past .009 -> .010).
    """
    candidates = []
    for name in os.listdir(image_dir):
        m = SEGMENT_RE.search(name)
        if m:
            candidates.append((int(m.group(1)), name))
    candidates.sort(key=lambda t: t[0])
    return [os.path.join(image_dir, name) for _, name in candidates]


def combine_split_images(image_dir, output_file, progress_cb=None, coc=None, cancel_event=None):
    """
    Stream-concatenate every split segment in image_dir into output_file,
    in numeric order. Hashes each segment and the combined output, then
    independently re-hashes the written file to verify nothing got
    corrupted in transit.

    Returns (result_dict_or_None, error_string_or_None). A non-fatal
    integrity warning is returned as the error string alongside a valid
    result_dict — callers should check `result["integrity_verified"]`.
    """
    try:
        segments = find_split_segments(image_dir)
        if not segments:
            return None, f"No split image segments (e.g. .001, .002, ...) found in {image_dir}"

        segment_numbers = [int(SEGMENT_RE.search(path).group(1)) for path in segments]
        expected_numbers = list(range(segment_numbers[0], segment_numbers[-1] + 1))
        if segment_numbers != expected_numbers:
            return None, "Split image segments have a missing or non-contiguous numeric part."

        output_file = os.path.abspath(output_file)
        segment_paths = {os.path.abspath(path) for path in segments}
        if output_file in segment_paths:
            return None, "The combined output must not overwrite an input segment."
        if os.path.exists(output_file):
            return None, f"Refusing to overwrite existing output file: {output_file}"

        total_size = sum(os.path.getsize(s) for s in segments)
        written = 0
        segment_hashes = []
        combined_hasher = hashlib.sha256()

        with open(output_file, "wb") as out:
            for seg in segments:
                seg_hasher = hashlib.sha256()
                with open(seg, "rb") as f:
                    while True:
                        _check_cancelled(cancel_event, "Image combination cancelled by user.")
                        chunk = f.read(4 * 1024 * 1024)
                        if not chunk:
                            break
                        out.write(chunk)
                        seg_hasher.update(chunk)
                        combined_hasher.update(chunk)
                        written += len(chunk)
                        if progress_cb:
                            progress_cb(written, total_size)
                segment_hashes.append({
                    "file": os.path.basename(seg),
                    "sha256": seg_hasher.hexdigest(),
                    "size": os.path.getsize(seg),
                })

        combined_sha256 = combined_hasher.hexdigest()
        # Independent verification pass: re-read the file we just wrote from disk.
        verify_hash = hash_file(output_file, algos=("sha256",))["sha256"]
        integrity_ok = verify_hash == combined_sha256

        result = {
            "output_file": output_file,
            "segments": segment_hashes,
            "combined_size": os.path.getsize(output_file),
            "combined_sha256": combined_sha256,
            "verify_sha256": verify_hash,
            "integrity_verified": integrity_ok,
        }

        if coc:
            coc.log_event(
                "IMAGE_COMBINED",
                f"Combined {len(segments)} segment(s) into {output_file}",
                extra={"sha256": combined_sha256, "integrity_verified": integrity_ok},
            )

        if not integrity_ok:
            return result, (
                "WARNING: the combined file's hash does not match the hash "
                "computed while writing it. The output file may be corrupt."
            )

        return result, None
    except OperationCancelled:
        try:
            if os.path.exists(output_file):
                os.remove(output_file)  # don't leave a half-written image on disk
        except Exception:
            logger.exception("Could not remove partial output file after cancellation")
        if coc:
            coc.log_event("IMAGE_COMBINE_CANCELLED", f"Image combination cancelled by user for {output_file}")
        raise
    except Exception as e:
        logger.exception("Error combining split images")
        return None, f"An error occurred while combining split image files: {e}"


# ---------------------------------------------------------------------------
# File-signature (magic-byte) verification
# ---------------------------------------------------------------------------
# A deliberately small, high-confidence set: enough to catch the common
# "renamed to hide it" trick without false-flagging exotic-but-legitimate
# formats we haven't listed. Extend as needed.
MAGIC_SIGNATURES = {
    ".jpg": [b"\xFF\xD8\xFF"], ".jpeg": [b"\xFF\xD8\xFF"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".gif": [b"GIF87a", b"GIF89a"],
    ".bmp": [b"BM"],
    ".pdf": [b"%PDF-"],
    ".zip": [b"PK\x03\x04", b"PK\x05\x06"],
    ".docx": [b"PK\x03\x04"], ".xlsx": [b"PK\x03\x04"], ".pptx": [b"PK\x03\x04"],
    ".exe": [b"MZ"], ".dll": [b"MZ"],
    ".rar": [b"Rar!\x1a\x07"],
    ".7z": [b"7z\xbc\xaf\x27\x1c"],
    ".gz": [b"\x1f\x8b"],
}

EWF_EXTENSIONS = {".e01", ".ex01", ".s01", ".l01"}


def is_probably_ewf(path):
    """Return true when the filename or EWF header identifies an EWF image."""
    if os.path.splitext(path)[1].lower() in EWF_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as image_file:
            return image_file.read(3) == b"EVF"
    except OSError:
        return False


def _open_image(image_path):
    if is_probably_ewf(image_path):
        if pyewf is None:
            raise RuntimeError(
                "EWF support is unavailable. Install the optional 'pyewf' package "
                "or export the evidence to raw format with ewfexport."
            )

        handle = pyewf.handle()
        handle.open([image_path])

        class EwfImgInfo(pytsk3.Img_Info):
            def __init__(self, ewf_handle):
                self._ewf_handle = ewf_handle
                super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

            def close(self):
                self._ewf_handle.close()

            def read(self, offset, size):
                self._ewf_handle.seek(offset)
                return self._ewf_handle.read(size)

            def get_size(self):
                return self._ewf_handle.get_media_size()

        return EwfImgInfo(handle)
    return pytsk3.Img_Info(image_path)


def _check_signature(entry, name):
    """
    Compare a file's first bytes against the expected magic number for its
    extension. Returns True (mismatch), False (matches or unknown-but-checked),
    or None (extension not in our table / content unreadable — not flagged).
    """
    ext = os.path.splitext(name)[1].lower()
    expected_sigs = MAGIC_SIGNATURES.get(ext)
    if not expected_sigs:
        return None
    try:
        if not entry.info.meta or entry.info.meta.size < 4:
            return None
        header = entry.read_random(0, min(16, entry.info.meta.size))
    except Exception:
        return None  # unreadable content (e.g. resident/sparse edge case) — don't guess
    return not any(header.startswith(sig) for sig in expected_sigs)


def _fmt_ts(epoch_val):
    try:
        return time.ctime(epoch_val) if epoch_val else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Disk image analysis (pytsk3-backed)
# ---------------------------------------------------------------------------
def analyze_image(image_path, coc=None, max_files=5000, progress_cb=None, cancel_event=None,
                  calculate_hashes=True):
    """
    Hash the image, then open it with The Sleuth Kit (pytsk3) and enumerate
    partitions and files: MACB timestamps, deleted-but-recoverable entries,
    and extension-vs-content signature mismatches.

    Raw/dd images and EWF images with the optional pyewf dependency are supported.
    An EWF image is never silently treated as a raw file. If the image can't be
    parsed as a filesystem, the raw metadata and hashes are still returned with
    an explicit filesystem warning.
    """
    if pytsk3 is None:
        return None, "pytsk3 is not installed — install it to enable filesystem parsing."

    try:
        file_name = os.path.basename(image_path)
        file_size = os.path.getsize(image_path)
        access_time = time.ctime(os.path.getatime(image_path))
        modified_time = time.ctime(os.path.getmtime(image_path))
        hashes = {}
        if calculate_hashes:
            hashes = hash_file(
                image_path, algos=("md5", "sha256"), progress_cb=progress_cb, cancel_event=cancel_event
            )

        result = {
            "file_name": file_name,
            "file_size": file_size,
            "access_time": access_time,
            "modified_time": modified_time,
            "partitions": [],
            "filesystem_error": None,
            "filesystem_parsed": False,
        }
        result.update(hashes)

        if progress_cb:
            progress_cb(1, 1, "Parsing filesystem structure (this may take a while)…")

        try:
            img = _open_image(image_path)
        except Exception as e:
            return None, f"Could not open evidence image '{file_name}': {e}"

        volumes = None
        try:
            vol_info = pytsk3.Volume_Info(img)
            volumes = [
                {"addr": p.addr, "desc": p.desc.decode(errors="replace"), "start": p.start, "len": p.len}
                for p in vol_info
            ]
        except Exception:
            volumes = None  # no partition table detected — treat as a single volume

        def enumerate_fs(fs):
            entries = []
            deleted_count = 0
            sig_mismatch_count = 0
            file_types = {}
            entries_seen = 0

            def walk(directory, path_prefix, depth=0):
                nonlocal deleted_count, sig_mismatch_count, entries_seen
                if depth > 15 or len(entries) >= max_files:
                    return
                for entry in directory:
                    if len(entries) >= max_files:
                        return
                    entries_seen += 1
                    if entries_seen % 200 == 0:
                        _check_cancelled(cancel_event, "Image analysis cancelled by user.")
                    if entry.info.name is None:
                        continue
                    try:
                        name = entry.info.name.name.decode(errors="replace")
                    except Exception:
                        continue
                    if name in (".", ".."):
                        continue

                    meta = entry.info.meta
                    is_deleted = bool(meta and (meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC))
                    is_dir = bool(meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR)
                    size = meta.size if meta else None
                    full_path = f"{path_prefix}/{name}"

                    sig_mismatch = None
                    if not is_dir:
                        ext = os.path.splitext(name)[1].lower()
                        file_types[ext or "(no extension)"] = file_types.get(ext or "(no extension)", 0) + 1
                        sig_mismatch = _check_signature(entry, name)
                        if sig_mismatch:
                            sig_mismatch_count += 1

                    entries.append({
                        "path": full_path,
                        "size": size,
                        "is_dir": is_dir,
                        "deleted": is_deleted,
                        "signature_mismatch": sig_mismatch,
                        "modified": _fmt_ts(getattr(meta, "mtime", None)) if meta else None,
                        "accessed": _fmt_ts(getattr(meta, "atime", None)) if meta else None,
                        "created": _fmt_ts(getattr(meta, "crtime", None)) if meta else None,
                        "changed": _fmt_ts(getattr(meta, "ctime", None)) if meta else None,
                    })
                    if is_deleted:
                        deleted_count += 1
                    if is_dir and not is_deleted:
                        try:
                            walk(entry.as_directory(), full_path, depth + 1)
                        except Exception:
                            pass  # unreadable/corrupt directory entry — skip, don't abort

            try:
                walk(fs.open_dir(path="/"), "")
            except OperationCancelled:
                raise
            except Exception as e:
                logger.warning("Could not walk filesystem: %s", e)

            return entries, deleted_count, sig_mismatch_count, file_types

        if volumes:
            for part in volumes:
                partition_result = {"info": part, "filesystem": None, "files": [], "deleted_files": 0,
                                    "sig_mismatch_count": 0, "file_types": {}}
                try:
                    fs = pytsk3.FS_Info(img, offset=part["start"] * 512)
                    entries, deleted, sig_mismatch, file_types = enumerate_fs(fs)
                    partition_result["filesystem"] = str(fs.info.ftype)
                    partition_result["files"] = entries
                    partition_result["deleted_files"] = deleted
                    partition_result["sig_mismatch_count"] = sig_mismatch
                    partition_result["file_types"] = file_types
                except OperationCancelled:
                    raise
                except Exception as e:
                    # normal for unallocated/extended partitions — not a hard failure
                    partition_result["filesystem_error"] = str(e)
                result["partitions"].append(partition_result)
        else:
            try:
                fs = pytsk3.FS_Info(img)
                entries, deleted, sig_mismatch, file_types = enumerate_fs(fs)
                result["partitions"].append({
                    "info": {"desc": "Whole image (no partition table)"},
                    "filesystem": str(fs.info.ftype),
                    "files": entries,
                    "deleted_files": deleted,
                    "sig_mismatch_count": sig_mismatch,
                    "file_types": file_types,
                })
            except OperationCancelled:
                raise
            except Exception as e:
                result["filesystem_error"] = f"Could not open image as a filesystem: {e}"

        filesystem_warnings = [
            p["filesystem_error"] for p in result["partitions"] if p.get("filesystem_error")
        ]
        if filesystem_warnings:
            result["filesystem_error"] = " | ".join(filesystem_warnings)
        result["filesystem_parsed"] = any(
            partition.get("filesystem") is not None for partition in result["partitions"]
        )

        if coc:
            total_files = sum(len(p.get("files", [])) for p in result["partitions"])
            total_deleted = sum(p.get("deleted_files", 0) for p in result["partitions"])
            total_mismatch = sum(p.get("sig_mismatch_count", 0) for p in result["partitions"])
            coc.log_event(
                "IMAGE_ANALYZED",
                f"Analyzed {file_name}: {total_files} entries enumerated, {total_deleted} deleted, "
                f"{total_mismatch} signature mismatches",
                extra={"sha256": hashes.get("sha256")} if hashes else None,
            )

        return result, None
    except OperationCancelled:
        if coc:
            coc.log_event("IMAGE_ANALYSIS_CANCELLED", f"Image analysis cancelled by user for {image_path}")
        raise
    except Exception as e:
        logger.exception("Error analyzing image")
        return None, f"An error occurred while analyzing the image: {e}"


def save_to_json(data, output_path):
    try:
        with open(output_path, "w") as f:
            json.dump(data, f, indent=4)
        return None
    except Exception as e:
        logger.exception("Error saving JSON")
        return f"An error occurred while saving to JSON: {e}"


# ---------------------------------------------------------------------------
# Drive analysis
# ---------------------------------------------------------------------------
def count_items(path, cancel_event=None, progress_cb=None):
    directories = 0
    files = 0
    folders = 0
    file_types = {}
    saw_root = False

    try:
        for root, _, files_list in os.walk(path):
            _check_cancelled(cancel_event, "Drive scan cancelled by user.")
            folders += 1
            saw_root = True
            for file in files_list:
                files += 1
                ext = os.path.splitext(file)[1].lower() or "(no extension)"
                file_types[ext] = file_types.get(ext, 0) + 1
            if progress_cb and folders % 50 == 0:
                progress_cb(0, None, f"Scanning… {folders} folders, {files} files so far")
    except OperationCancelled:
        raise
    except Exception:
        logger.exception("Error walking path %s", path)

    directories = max(folders - 1, 0) if saw_root else 0
    return directories, files, folders, file_types


def get_drive_file_system(drive_path):
    try:
        fs_info = ctypes.create_unicode_buffer(255)
        ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(drive_path), fs_info, len(fs_info)
        )
        return fs_info.value.strip() or "Unknown"
    except Exception:
        logger.exception("Error getting file system info for %s", drive_path)
        return "Unknown"


def get_disk_space_info(drive_path):
    free_bytes = ctypes.c_ulonglong(0)
    total_bytes = ctypes.c_ulonglong(0)
    try:
        ctypes.windll.kernel32.GetDiskFreeSpaceExW(
            ctypes.c_wchar_p(drive_path), None, ctypes.pointer(total_bytes), ctypes.pointer(free_bytes)
        )
    except Exception:
        logger.exception("Error getting disk space info for %s", drive_path)
    return total_bytes.value / (1024 ** 3), free_bytes.value / (1024 ** 3)


def list_logical_drives():
    drives = []
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in range(26):
            if bitmask & (1 << letter):
                drives.append(chr(65 + letter) + ":\\")
    except Exception:
        logger.exception("Error listing logical drives")
    return drives


def analyze_drive(drive_path, coc=None, cancel_event=None, progress_cb=None):
    if not os.path.exists(drive_path):
        return None, f"Drive path does not exist: {drive_path}"

    file_system = get_drive_file_system(drive_path)
    try:
        directories, files, folders, file_types = count_items(drive_path, cancel_event=cancel_event,
                                                               progress_cb=progress_cb)
    except OperationCancelled:
        if coc:
            coc.log_event("DRIVE_SCAN_CANCELLED", f"Drive scan cancelled by user for {drive_path}")
        raise
    total_gb, free_gb = get_disk_space_info(drive_path)

    drive_info = {
        "drive_path": drive_path,
        "file_system": file_system,
        "total_space_gb": round(total_gb, 2),
        "free_space_gb": round(free_gb, 2),
        "directories": directories,
        "files": files,
        "folders": folders,
        "file_types": file_types,
        "is_logical_drive": drive_path in list_logical_drives(),
    }

    if coc:
        coc.log_event(
            "DRIVE_ANALYZED",
            f"Analyzed drive {drive_path}",
            extra={"files": files, "folders": folders},
        )

    return drive_info, None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
def read_registry_value(key, subkey, value_name):
    try:
        registry_key = winreg.OpenKey(key, subkey)
        value, _ = winreg.QueryValueEx(registry_key, value_name)
        winreg.CloseKey(registry_key)
        return value
    except FileNotFoundError:
        return None
    except Exception:
        logger.exception("Error reading registry value %s\\%s", subkey, value_name)
        return None


def get_system_information():
    return {
        "OSVersion": read_registry_value(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName"
        ),
        "ComputerName": read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
            "ComputerName",
        ),
        "Processor": read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            "ProcessorNameString",
        ),
        "Memory": read_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\RESOURCEMAP\System Resources\Physical Memory",
            "MemoryReserved",
        ),
        "GraphicsCard": read_registry_value(
            winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\VIDEO", "\\Device\\Video0"
        ),
    }


def read_registry_subkey_values(key, subkey):
    subkey_values = {}
    try:
        registry_key = winreg.OpenKey(key, subkey)
        index = 0
        while True:
            try:
                value_name, value_data, _ = winreg.EnumValue(registry_key, index)
                subkey_values[value_name] = value_data
                index += 1
            except OSError:
                break
        winreg.CloseKey(registry_key)
    except FileNotFoundError:
        pass
    except Exception:
        logger.exception("Error reading registry subkey values for %s", subkey)
    return subkey_values


def read_registry_subkey(key, subkey):
    try:
        registry_key = winreg.OpenKey(key, subkey)
        subkey_info = {}
        index = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(registry_key, index)
                subkey_info[subkey_name] = read_registry_subkey_values(registry_key, subkey_name)
                index += 1
            except OSError:
                break
        winreg.CloseKey(registry_key)
        return subkey_info
    except FileNotFoundError:
        return None
    except Exception:
        logger.exception("Error reading registry subkey %s", subkey)
        return None


def get_installed_software():
    uninstall_subkey = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    return {
        "LocalMachine": read_registry_subkey(winreg.HKEY_LOCAL_MACHINE, uninstall_subkey),
        "CurrentUser": read_registry_subkey(winreg.HKEY_CURRENT_USER, uninstall_subkey),
    }


def retrieve_registry_info(coc=None):
    result = []

    key = winreg.HKEY_CURRENT_USER
    subkey = r"Control Panel\Desktop"
    result.append("User Interface Settings:")
    result.append(f"Wallpaper: {read_registry_value(key, subkey, 'Wallpaper')}")
    result.append(f"Screen Saver: {read_registry_value(key, subkey, 'SCRNSAVE.EXE')}")
    result.append(f"Screen Saver Timeout (seconds): {read_registry_value(key, subkey, 'ScreenSaveTimeOut')}\n")

    system_info = get_system_information()
    result.append("System Information:")
    for k, v in system_info.items():
        result.append(f"{k}: {v}")

    software_info = get_installed_software()
    result.append("\nInstalled Software Information:")
    for location, software_list in software_info.items():
        result.append(f"\nLocation: {location}")
        if not software_list:
            result.append("  (none found)")
            continue
        for software_name, software_details in software_list.items():
            result.append(f"\nSoftware Name: {software_name}")
            for k, v in software_details.items():
                result.append(f"{k}: {v}")

    text = "\n".join(result)

    if coc:
        coc.log_event("REGISTRY_READ", "Read system, UI, and installed-software registry information")

    return text


def build_executive_summary(session_data):
    """A short plain-language paragraph for readers who won't touch the raw data tables."""
    sentences = []

    drives = session_data.get("drives") or {}
    if drives:
        names = ", ".join(drives.keys())
        sentences.append(f"{len(drives)} local drive(s) were scanned ({names}).")

    img = session_data.get("image_analysis")
    if img:
        total_files = sum(len(p.get("files", [])) for p in img.get("partitions", []))
        total_deleted = sum(p.get("deleted_files", 0) for p in img.get("partitions", []))
        total_mismatch = sum(p.get("sig_mismatch_count", 0) for p in img.get("partitions", []))
        sentence = (
            f"The disk image '{img.get('file_name')}' ({img.get('file_size', 0):,} bytes) was hashed "
            f"(SHA-256: {img.get('sha256', 'n/a')})."
        )
        if img.get("filesystem_parsed"):
            sentence += f" Its file system was parsed, enumerating {total_files:,} entries."
        else:
            sentence += " Its file system was not parsed; treat file enumeration as unavailable."
        if total_deleted:
            sentence += f" {total_deleted:,} of those are deleted items that may still be recoverable."
        if total_mismatch:
            sentence += (
                f" {total_mismatch:,} file(s) had content that did not match their file extension, "
                "which can indicate deliberate disguising and warrants closer review."
            )
        sentences.append(sentence)

    if session_data.get("registry_info"):
        sentences.append("Windows Registry system, user-interface, and installed-software information was collected.")

    evidence = session_data.get("evidence_metadata")
    if evidence:
        sentences.append(f"Evidence file '{evidence.get('file_name')}' metadata was recorded.")

    if not sentences:
        sentences.append("No analysis has been performed yet in this session.")

    return " ".join(sentences)


# ---------------------------------------------------------------------------
# HTML report export
# ---------------------------------------------------------------------------
def generate_html_report(coc, session_data, output_path, max_files_listed=2000):
    """Build a single self-contained HTML report from everything collected this session."""

    def esc(x):
        return html.escape(str(x))

    parts = [f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Forensic Report - Case {esc(coc.case_number)}</title>
<style>
body {{ font-family: Consolas, monospace; background:#111; color:#eee; padding:20px; }}
h1,h2,h3 {{ color:#7fd; }}
table {{ border-collapse: collapse; width:100%; margin-bottom:20px; }}
td, th {{ border:1px solid #444; padding:6px 10px; text-align:left; font-size:13px; }}
th {{ background:#222; }}
tr.warn {{ color:#f66; }}
pre {{ background:#1a1a1a; padding:10px; overflow-x:auto; white-space: pre-wrap; }}
</style></head><body>"""]

    parts.append("<h1>Forensic Analysis Report</h1>")
    parts.append(
        f"<p><b>Case Number:</b> {esc(coc.case_number)}<br>"
        f"<b>Examiner:</b> {esc(coc.examiner)}<br>"
        f"<b>Report Generated (UTC):</b> {esc(datetime.now(timezone.utc).isoformat())}<br>"
        f"<b>Tool:</b> {esc(TOOL_NAME)} v{esc(TOOL_VERSION)} (hashing: MD5 + SHA-256; "
        f"filesystem parsing: The Sleuth Kit / pytsk3)</p>"
    )

    parts.append("<h2>Summary</h2>")
    parts.append(f"<p>{esc(build_executive_summary(session_data))}</p>")

    evidence = session_data.get("evidence_metadata")
    if evidence:
        parts.append("<h2>Evidence File Metadata</h2><table>")
        for key, value in evidence.items():
            parts.append(f"<tr><th>{esc(key)}</th><td>{esc(value)}</td></tr>")
        parts.append("</table>")

    if session_data.get("drives"):
        parts.append("<h2>Drive Analysis</h2>")
        for drive, info in session_data["drives"].items():
            parts.append(f"<h3>{esc(drive)}</h3><table>")
            for k, v in (info or {}).items():
                if k == "file_types":
                    continue
                parts.append(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>")
            parts.append("</table>")
            if info and info.get("file_types"):
                parts.append("<table><tr><th>Extension</th><th>Count</th></tr>")
                for ext, count in sorted(info["file_types"].items(), key=lambda x: -x[1]):
                    parts.append(f"<tr><td>{esc(ext)}</td><td>{esc(count)}</td></tr>")
                parts.append("</table>")

    img = session_data.get("image_analysis")
    if img:
        parts.append("<h2>Disk Image Analysis</h2><table>")
        for k in ("file_name", "file_size", "md5", "sha256", "access_time", "modified_time",
              "filesystem_parsed", "filesystem_error"):
            if k in img:
                parts.append(f"<tr><th>{esc(k)}</th><td>{esc(img[k])}</td></tr>")
        parts.append("</table>")
        for part in img.get("partitions", []):
            desc = part.get("info", {}).get("desc", "Partition")
            parts.append(f"<h3>{esc(desc)}</h3>")
            parts.append(
                f"<p>Filesystem: {esc(part.get('filesystem'))} — "
                f"{len(part.get('files', []))} entries enumerated, "
                f"{part.get('deleted_files', 0)} deleted, "
                f"{part.get('sig_mismatch_count', 0)} signature mismatch(es)</p>"
            )
            files = part.get("files", [])
            if files:
                parts.append(
                    "<table><tr><th>Path</th><th>Size</th><th>Modified</th>"
                    "<th>Deleted?</th><th>Signature Mismatch?</th></tr>"
                )
                for f in files[:max_files_listed]:
                    flagged = f.get("deleted") or f.get("signature_mismatch")
                    row_class = ' class="warn"' if flagged else ""
                    parts.append(
                        f"<tr{row_class}><td>{esc(f['path'])}</td><td>{esc(f.get('size'))}</td>"
                        f"<td>{esc(f.get('modified'))}</td><td>{esc(f.get('deleted'))}</td>"
                        f"<td>{esc(f.get('signature_mismatch'))}</td></tr>"
                    )
                parts.append("</table>")
                if len(files) > max_files_listed:
                    parts.append(f"<p>… and {len(files) - max_files_listed} more entries not shown.</p>")

    if session_data.get("registry_info"):
        parts.append("<h2>Registry Information</h2><pre>")
        parts.append(esc(session_data["registry_info"]))
        parts.append("</pre>")

    parts.append("<h2>Chain of Custody Log</h2><pre>")
    parts.append(esc(coc.as_text()))
    parts.append("</pre>")

    parts.append("</body></html>")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))

    coc.log_event("REPORT_EXPORTED", f"Report exported to {output_path}")
    return output_path
