from __future__ import annotations

import csv
import datetime as dt
import io
import json
import math
import mimetypes
import os
import re
import shutil
import sqlite3
import stat as stat_module
import subprocess
import threading
import time
import warnings
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from email.parser import BytesHeaderParser
from pathlib import Path, PurePosixPath

import imagehash
import magic
import olefile
from blake3 import blake3
from PIL import Image, ImageOps, UnidentifiedImageError
from pillow_heif import register_heif_opener
from pypdf import PdfReader

register_heif_opener()
Image.MAX_IMAGE_PIXELS = 250_000_000
warnings.simplefilter("error", Image.DecompressionBombWarning)

IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".jpe", ".png", ".gif", ".bmp", ".tif", ".tiff",
    ".webp", ".heic", ".heif", ".avif",
}
RAW_EXTENSIONS = {".dng", ".cr2", ".cr3", ".nef", ".arw", ".rw2", ".orf", ".raf", ".pef", ".srw"}
VIDEO_EXTENSIONS = {
    ".mp4", ".mov", ".m4v", ".avi", ".mkv", ".wmv", ".3gp", ".3gpp",
    ".mts", ".m2ts", ".webm", ".mpg", ".mpeg", ".vob", ".flv", ".lrv",
}
OFFICE_MARKERS = {
    ".docx": "word/document.xml",
    ".xlsx": "xl/workbook.xml",
    ".pptx": "ppt/presentation.xml",
}
CAMERA_PREFIXES = ("img_", "dsc_", "dscf", "pxl_", "mvimg_", "100_", "sam_")
SCREENSHOT_WORDS = ("screenshot", "screen shot", "screencap", "snip", "capture")
DOWNLOAD_WORDS = ("download", "received", "messenger", "whatsapp", "telegram")
THUMB_WORDS = ("thumb", "thumbnail", "preview", "cache", "tmp", "temp")
IGNORED_SYSTEM_DIRECTORIES = {"system volume information"}
SYNTHETIC_FOLDER_NAMES = {
    "0 byte", "all files", "dated photos", "dated photos and screenshots",
    "lost and found", "photos with sizes", "img w pixel size", "folder",
}
SYSTEM_FOLDER_NAMES = {
    "$recycle.bin", "program files", "program files (x86)", "windows", "system32",
    "appdata", "cache", "temp", "temporary internet files", "node_modules",
}
VIDEO_ANALYSIS_VERSION = 1


@dataclass
class DateProposal:
    value: str | None = None
    source: str | None = None
    confidence: int = 0
    reason: str | None = None


@dataclass
class TraversalDiagnostics:
    directories_scanned: int = 0
    errors: int = 0
    first_error: str | None = None
    ignored_system_directories: int = 0

    def record_error(self, path: Path | str, exc: OSError) -> None:
        self.errors += 1
        if self.first_error is None:
            self.first_error = f"{path}: {exc}"


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=60)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def initialize(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with connect(db_path) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS files (
              id INTEGER PRIMARY KEY,
              path TEXT NOT NULL UNIQUE,
              relative_path TEXT NOT NULL,
              name TEXT NOT NULL,
              extension TEXT,
              size INTEGER NOT NULL,
              mtime_ns INTEGER NOT NULL,
              seen_scan TEXT,
              mime TEXT,
              detected_extension TEXT,
              validation TEXT DEFAULT 'unchecked',
              validation_detail TEXT,
              content_hash TEXT,
              is_image INTEGER DEFAULT 0,
              width INTEGER,
              height INTEGER,
              megapixels REAL,
              phash TEXT,
              exif_date TEXT,
              exif_make TEXT,
              exif_model TEXT,
              filename_date TEXT,
              date_confidence INTEGER DEFAULT 0,
              date_reason TEXT,
              category TEXT,
              category_confidence INTEGER DEFAULT 0,
              category_reason TEXT,
              quality_score REAL DEFAULT 0,
              exact_group TEXT,
              similar_group INTEGER,
              known_good_match INTEGER DEFAULT 0,
              known_good_count INTEGER DEFAULT 0,
              known_good_library TEXT,
              known_good_path TEXT,
              decision TEXT DEFAULT 'undecided',
              exported_path TEXT,
              ai_caption TEXT,
              ai_people TEXT,
              ai_objects TEXT,
              ai_ocr_text TEXT,
              ai_tags TEXT,
              ai_model TEXT,
              ai_updated_at TEXT,
              media_kind TEXT DEFAULT 'other',
              media_origin TEXT DEFAULT 'unknown',
              sensitivity TEXT DEFAULT 'unknown',
              video_duration REAL,
              video_width INTEGER,
              video_height INTEGER,
              video_fps REAL,
              video_codec TEXT,
              audio_codec TEXT,
              video_creation_date TEXT,
              video_analysis_version INTEGER DEFAULT 0,
              updated_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_files_size ON files(size);
            CREATE INDEX IF NOT EXISTS idx_files_hash ON files(content_hash);
            CREATE INDEX IF NOT EXISTS idx_files_size_hash ON files(size,content_hash);
            CREATE INDEX IF NOT EXISTS idx_files_exact ON files(exact_group);
            CREATE INDEX IF NOT EXISTS idx_files_similar ON files(similar_group);
            CREATE INDEX IF NOT EXISTS idx_files_category ON files(category);
            CREATE TABLE IF NOT EXISTS directories (
              id INTEGER PRIMARY KEY,
              path TEXT NOT NULL UNIQUE,
              relative_path TEXT NOT NULL,
              parent_relative_path TEXT,
              name TEXT NOT NULL,
              mtime_ns INTEGER,
              ctime_ns INTEGER,
              mode INTEGER,
              uid INTEGER,
              gid INTEGER,
              status TEXT NOT NULL DEFAULT 'available',
              read_error TEXT,
              seen_scan TEXT,
              updated_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_directories_parent ON directories(parent_relative_path);
            CREATE INDEX IF NOT EXISTS idx_directories_status ON directories(status);
            CREATE TABLE IF NOT EXISTS reference_files (
              id INTEGER PRIMARY KEY,
              library TEXT NOT NULL,
              path TEXT NOT NULL UNIQUE,
              relative_path TEXT NOT NULL,
              size INTEGER NOT NULL,
              mtime_ns INTEGER NOT NULL,
              seen_scan TEXT,
              content_hash TEXT,
              hash_error TEXT,
              updated_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_reference_size ON reference_files(size);
            CREATE INDEX IF NOT EXISTS idx_reference_hash ON reference_files(content_hash);
            CREATE INDEX IF NOT EXISTS idx_reference_size_hash ON reference_files(size,content_hash);
            CREATE INDEX IF NOT EXISTS idx_reference_library ON reference_files(library);
            CREATE TABLE IF NOT EXISTS known_good_matches (
              file_id INTEGER NOT NULL,
              reference_file_id INTEGER NOT NULL,
              library TEXT NOT NULL,
              relative_path TEXT NOT NULL,
              confidence INTEGER NOT NULL DEFAULT 100,
              updated_at TEXT NOT NULL,
              PRIMARY KEY(file_id,reference_file_id)
            );
            CREATE INDEX IF NOT EXISTS idx_known_good_matches_file ON known_good_matches(file_id);
            CREATE TABLE IF NOT EXISTS file_facets (
              file_id INTEGER NOT NULL,
              facet_type TEXT NOT NULL,
              value TEXT NOT NULL,
              confidence INTEGER NOT NULL DEFAULT 0,
              source TEXT NOT NULL,
              reason TEXT,
              updated_at TEXT NOT NULL,
              PRIMARY KEY(file_id,facet_type,value,source)
            );
            CREATE INDEX IF NOT EXISTS idx_file_facets_type_value ON file_facets(facet_type,value);
            CREATE TABLE IF NOT EXISTS file_relationships (
              id INTEGER PRIMARY KEY,
              file_id INTEGER NOT NULL,
              related_file_id INTEGER NOT NULL,
              relationship TEXT NOT NULL,
              confidence INTEGER NOT NULL DEFAULT 0,
              evidence TEXT,
              updated_at TEXT NOT NULL,
              UNIQUE(file_id,related_file_id,relationship)
            );
            CREATE INDEX IF NOT EXISTS idx_file_relationships_file ON file_relationships(file_id);
            CREATE TABLE IF NOT EXISTS reconstruction_proposals (
              file_id INTEGER PRIMARY KEY,
              proposed_path TEXT NOT NULL,
              confidence INTEGER NOT NULL DEFAULT 0,
              basis TEXT NOT NULL,
              reason TEXT,
              status TEXT NOT NULL DEFAULT 'proposed',
              review_state TEXT NOT NULL DEFAULT 'pending',
              user_path TEXT,
              review_note TEXT,
              reviewed_at TEXT,
              updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_reconstruction_status ON reconstruction_proposals(status);
            CREATE TABLE IF NOT EXISTS reconstruction_directories (
              directory_id INTEGER PRIMARY KEY,
              proposed_path TEXT NOT NULL,
              confidence INTEGER NOT NULL DEFAULT 0,
              basis TEXT NOT NULL,
              reason TEXT,
              status TEXT NOT NULL DEFAULT 'included',
              updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_reconstruction_directories_status
              ON reconstruction_directories(status);
            CREATE TABLE IF NOT EXISTS folder_context (
              directory_id INTEGER PRIMARY KEY,
              name TEXT NOT NULL,
              relative_path TEXT NOT NULL,
              descendant_files INTEGER NOT NULL DEFAULT 0,
              descendant_bytes INTEGER NOT NULL DEFAULT 0,
              zero_files INTEGER NOT NULL DEFAULT 0,
              suggestion_score REAL NOT NULL DEFAULT 0,
              review_status TEXT NOT NULL DEFAULT 'unreviewed',
              user_label TEXT,
              notes TEXT,
              updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_folder_context_score ON folder_context(suggestion_score DESC);
            CREATE TABLE IF NOT EXISTS recovery_context (
              id INTEGER PRIMARY KEY,
              context_type TEXT NOT NULL,
              label TEXT NOT NULL,
              details TEXT,
              match_text TEXT,
              destination TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ai_provider_settings (
              id INTEGER PRIMARY KEY CHECK(id=1),
              provider_id TEXT NOT NULL DEFAULT 'custom',
              provider_name TEXT NOT NULL DEFAULT 'Local AI',
              endpoint TEXT,
              model TEXT,
              api_key_env TEXT,
              enabled INTEGER NOT NULL DEFAULT 0,
              allow_cloud_media INTEGER NOT NULL DEFAULT 0,
              allow_sensitive_media INTEGER NOT NULL DEFAULT 0,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ai_runs (
              id INTEGER PRIMARY KEY,
              file_id INTEGER,
              provider_name TEXT,
              model TEXT,
              status TEXT NOT NULL,
              request_kind TEXT NOT NULL,
              response_json TEXT,
              error TEXT,
              created_at TEXT NOT NULL,
              completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS review_questions (
              id INTEGER PRIMARY KEY,
              file_id INTEGER,
              source TEXT NOT NULL,
              question TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'open',
              answer TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_review_questions_status ON review_questions(status);
            CREATE TABLE IF NOT EXISTS ai_structure_suggestions (
              id INTEGER PRIMARY KEY,
              suggestion_type TEXT NOT NULL,
              directory_id INTEGER,
              relative_path TEXT,
              review_status TEXT,
              user_label TEXT,
              match_text TEXT,
              destination TEXT,
              confidence INTEGER NOT NULL DEFAULT 0,
              reason TEXT,
              source TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'pending',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ai_structure_suggestions_status
              ON ai_structure_suggestions(status);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS actions (
              id INTEGER PRIMARY KEY,
              created_at TEXT NOT NULL,
              action TEXT NOT NULL,
              file_id INTEGER,
              source_path TEXT,
              destination_path TEXT,
              status TEXT NOT NULL,
              detail TEXT
            );
            """
        )
        existing_columns = {row[1] for row in db.execute("PRAGMA table_info(files)")}
        migrations = {
            "ai_caption": "TEXT", "ai_people": "TEXT", "ai_objects": "TEXT", "ai_ocr_text": "TEXT",
            "ai_tags": "TEXT", "ai_model": "TEXT", "ai_updated_at": "TEXT",
            "known_good_match": "INTEGER DEFAULT 0", "known_good_count": "INTEGER DEFAULT 0",
            "known_good_library": "TEXT", "known_good_path": "TEXT",
            "ctime_ns": "INTEGER", "mode": "INTEGER", "uid": "INTEGER", "gid": "INTEGER",
            "media_kind": "TEXT DEFAULT 'other'", "media_origin": "TEXT DEFAULT 'unknown'",
            "sensitivity": "TEXT DEFAULT 'unknown'", "video_duration": "REAL",
            "video_width": "INTEGER", "video_height": "INTEGER", "video_fps": "REAL",
            "video_codec": "TEXT", "audio_codec": "TEXT", "video_creation_date": "TEXT",
            "video_analysis_version": "INTEGER DEFAULT 0",
        }
        for column, definition in migrations.items():
            if column not in existing_columns:
                db.execute(f"ALTER TABLE files ADD COLUMN {column} {definition}")
        proposal_columns = {row[1] for row in db.execute("PRAGMA table_info(reconstruction_proposals)")}
        proposal_migrations = {
            "review_state": "TEXT NOT NULL DEFAULT 'pending'",
            "user_path": "TEXT",
            "review_note": "TEXT",
            "reviewed_at": "TEXT",
        }
        for column, definition in proposal_migrations.items():
            if column not in proposal_columns:
                db.execute(f"ALTER TABLE reconstruction_proposals ADD COLUMN {column} {definition}")
        context_columns = {row[1] for row in db.execute("PRAGMA table_info(recovery_context)")}
        for column in ("match_text", "destination"):
            if column not in context_columns:
                db.execute(f"ALTER TABLE recovery_context ADD COLUMN {column} TEXT")
        provider_columns = {row[1] for row in db.execute("PRAGMA table_info(ai_provider_settings)")}
        if "provider_id" not in provider_columns:
            db.execute("ALTER TABLE ai_provider_settings ADD COLUMN provider_id TEXT NOT NULL DEFAULT 'custom'")
        db.execute("CREATE INDEX IF NOT EXISTS idx_files_known_good ON files(known_good_match)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_files_media_kind ON files(media_kind)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_files_media_origin ON files(media_origin)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_reconstruction_review ON reconstruction_proposals(review_state)")
        video_extensions = tuple(sorted(VIDEO_EXTENSIONS))
        placeholders = ",".join("?" for _ in video_extensions)
        db.execute(
            f"""UPDATE files SET media_kind='video',category='Videos',category_confidence=96,
                   category_reason='video MIME or extension'
                WHERE lower(extension) IN ({placeholders}) OR mime LIKE 'video/%'""",
            video_extensions,
        )


def file_blake3(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    digest = blake3()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def sniff_mime(path: Path) -> str:
    try:
        return magic.from_file(str(path), mime=True) or "application/octet-stream"
    except Exception:
        return mimetypes.guess_type(path.name)[0] or "application/octet-stream"


def infer_extension(mime: str) -> str | None:
    aliases = {
        "image/jpeg": ".jpg", "image/png": ".png", "image/gif": ".gif",
        "image/tiff": ".tif", "image/webp": ".webp", "image/heic": ".heic",
        "application/pdf": ".pdf", "message/rfc822": ".eml",
        "application/zip": ".zip",
    }
    return aliases.get(mime) or mimetypes.guess_extension(mime)


def parse_filename_date(name: str, current_year: int | None = None) -> DateProposal:
    """Only parses unambiguous, year-first recovery/camera naming patterns."""
    stem = Path(name).stem
    current_year = current_year or dt.datetime.now().year
    patterns = [
        (r"(?<!\d)(?P<y>19\d{2}|20\d{2})[-_.]?(?P<m>0[1-9]|1[0-2])[-_.]?(?P<d>0[1-9]|[12]\d|3[01])[T _.-]?(?P<h>[01]\d|2[0-3])[-_.:]?(?P<mi>[0-5]\d)[-_.:]?(?P<s>[0-5]\d)(?!\d)", 95, "year-first date and time in filename"),
        (r"(?<!\d)(?P<y>19\d{2}|20\d{2})[-_.]?(?P<m>0[1-9]|1[0-2])[-_.]?(?P<d>0[1-9]|[12]\d|3[01])(?!\d)", 85, "year-first date in filename"),
    ]
    for pattern, confidence, reason in patterns:
        match = re.search(pattern, stem, flags=re.IGNORECASE)
        if not match:
            continue
        parts = match.groupdict(default="0")
        try:
            value = dt.datetime(
                int(parts["y"]), int(parts["m"]), int(parts["d"]),
                int(parts.get("h") or 0), int(parts.get("mi") or 0), int(parts.get("s") or 0),
            )
        except ValueError:
            continue
        if not 1990 <= value.year <= current_year + 1:
            continue
        return DateProposal(value.isoformat(timespec="seconds"), "filename", confidence, reason)
    return DateProposal(reason="no unambiguous year-first filename date")


def normalize_exif_date(raw: object) -> str | None:
    if not raw:
        return None
    text = str(raw).strip()
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            value = dt.datetime.strptime(text[:19], fmt)
            if 1990 <= value.year <= dt.datetime.now().year + 1:
                return value.isoformat(timespec="seconds")
        except ValueError:
            pass
    return None


def infer_media_kind(path: Path, mime: str | None = None) -> str:
    extension = path.suffix.lower()
    mime = mime or ""
    if extension in VIDEO_EXTENSIONS or mime.startswith("video/"):
        return "video"
    if extension in IMAGE_EXTENSIONS or extension in RAW_EXTENSIONS or mime.startswith("image/"):
        return "photo"
    if extension in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf"}:
        return "document"
    if extension in {".eml", ".msg", ".mbox"} or mime == "message/rfc822":
        return "email"
    if mime.startswith("audio/"):
        return "audio"
    return "other"


def infer_media_origin(path: Path, metadata: dict | None = None) -> tuple[str, int, str]:
    metadata = metadata or {}
    lower = str(path).casefold()
    name = path.name.casefold()
    if "snapchat" in lower or "snapsave" in lower or name.startswith("snap-"):
        return "snapchat", 94, "Snapchat or SnapSave path/name"
    if "screenrecord" in name or "screen_record" in name or "screen recording" in name:
        return "screen_recording", 94, "screen-recording filename"
    if any(word in name for word in SCREENSHOT_WORDS):
        return "screenshot", 96, "screenshot filename"
    if any(word in lower for word in DOWNLOAD_WORDS) or any(
        word in lower for word in ("wallpaper", "background", "browser cache", "internet files")
    ):
        return "downloaded", 78, "download/message/cache path"
    if metadata.get("exif_make") or metadata.get("exif_model") or name.startswith(CAMERA_PREFIXES):
        return "camera", 88 if (metadata.get("exif_make") or metadata.get("exif_model")) else 72, "camera metadata or filename"
    return "unknown", 0, "insufficient deterministic origin evidence"


def _parse_frame_rate(raw: object) -> float | None:
    text = str(raw or "")
    try:
        if "/" in text:
            numerator, denominator = text.split("/", 1)
            value = float(numerator) / float(denominator)
        else:
            value = float(text)
        return round(value, 3) if math.isfinite(value) and value > 0 else None
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def analyze_video(path: Path) -> dict:
    try:
        result = subprocess.run(
            [
                "ffprobe", "-v", "error", "-print_format", "json",
                "-show_format", "-show_streams", str(path),
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=45,
        )
        if result.returncode != 0:
            raise ValueError((result.stderr or "FFprobe could not read the video").strip())
        payload = json.loads(result.stdout or "{}")
        streams = payload.get("streams") or []
        video = next((item for item in streams if item.get("codec_type") == "video"), None)
        audio = next((item for item in streams if item.get("codec_type") == "audio"), None)
        if not video:
            raise ValueError("no decodable video stream found")
        format_info = payload.get("format") or {}
        duration_raw = format_info.get("duration") or video.get("duration")
        try:
            duration = round(float(duration_raw), 3) if duration_raw is not None else None
        except (TypeError, ValueError):
            duration = None
        tags = {}
        tags.update(format_info.get("tags") or {})
        tags.update(video.get("tags") or {})
        creation = normalize_exif_date(tags.get("creation_time") or tags.get("date"))
        width = int(video.get("width") or 0) or None
        height = int(video.get("height") or 0) or None
        return {
            "validation": "valid", "validation_detail": "video container and primary stream verified",
            "is_image": 0, "width": width, "height": height,
            "megapixels": round(width * height / 1_000_000, 3) if width and height else None,
            "phash": None, "exif_date": None, "exif_make": None, "exif_model": None,
            "video_duration": duration, "video_width": width, "video_height": height,
            "video_fps": _parse_frame_rate(video.get("avg_frame_rate") or video.get("r_frame_rate")),
            "video_codec": video.get("codec_name"), "audio_codec": audio.get("codec_name") if audio else None,
            "video_creation_date": creation, "video_analysis_version": VIDEO_ANALYSIS_VERSION,
        }
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        return {
            "validation": "corrupt", "validation_detail": str(exc)[:300], "is_image": 0,
            "width": None, "height": None, "megapixels": None, "phash": None,
            "exif_date": None, "exif_make": None, "exif_model": None,
            "video_duration": None, "video_width": None, "video_height": None,
            "video_fps": None, "video_codec": None, "audio_codec": None,
            "video_creation_date": None, "video_analysis_version": VIDEO_ANALYSIS_VERSION,
        }


def validate_nonimage(path: Path, extension: str) -> tuple[str, str]:
    try:
        if extension == ".pdf":
            result = subprocess.run(
                ["qpdf", "--check", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=60,
            )
            if result.returncode not in {0, 3}:
                return "corrupt", (result.stderr or result.stdout).strip()[:300]
            try:
                reader = PdfReader(str(path), strict=False)
                pages = len(reader.pages)
            except Exception:
                pages = "unknown"
            return "valid", f"PDF structure verified, {pages} page(s)"
        if extension in OFFICE_MARKERS:
            with zipfile.ZipFile(path) as archive:
                if OFFICE_MARKERS[extension] not in archive.namelist():
                    return "corrupt", f"missing {OFFICE_MARKERS[extension]}"
            return "valid", "Office package structure verified (quick check)"
        if extension in {".zip", ".jar", ".epub"}:
            with zipfile.ZipFile(path) as archive:
                members = len(archive.infolist())
            return "valid", f"ZIP central directory verified, {members} member(s)"
        if extension == ".eml":
            with path.open("rb") as stream:
                message = BytesHeaderParser().parsebytes(stream.read(1024 * 1024), headersonly=True)
            return "valid", f"email headers parsed; subject={message.get('subject', '')[:80]}"
        if extension == ".msg":
            return ("valid", "OLE container verified") if olefile.isOleFile(path) else ("corrupt", "not a valid OLE container")
    except Exception as exc:
        return "corrupt", str(exc)[:300]
    return "unchecked", "format-specific validation not configured"


def analyze_image(path: Path) -> dict:
    try:
        with Image.open(path) as image:
            width, height = image.size
            exif = image.getexif()
            exif_date = normalize_exif_date(exif.get(36867) or exif.get(36868) or exif.get(306))
            make = str(exif.get(271) or "").strip() or None
            model = str(exif.get(272) or "").strip() or None
            # Decode at review resolution instead of allocating the full photo solely for pHash.
            image.draft("RGB", (512, 512))
            image = ImageOps.exif_transpose(image)
            image.thumbnail((512, 512), Image.Resampling.LANCZOS)
            image.load()
            perceptual = str(imagehash.phash(image.convert("RGB"), hash_size=8))
        pixels = max(width * height, 1)
        return {
            "validation": "valid", "validation_detail": "image decoded successfully",
            "is_image": 1, "width": width, "height": height,
            "megapixels": round(pixels / 1_000_000, 3), "phash": perceptual,
            "exif_date": exif_date, "exif_make": make, "exif_model": model,
        }
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError) as exc:
        return {
            "validation": "corrupt", "validation_detail": str(exc)[:300],
            "is_image": 1, "width": None, "height": None, "megapixels": None,
            "phash": None, "exif_date": None, "exif_make": None, "exif_model": None,
        }


def analyze_raw(path: Path) -> dict:
    try:
        result = subprocess.run(
            ["exiftool", "-j", "-ImageWidth", "-ImageHeight", "-DateTimeOriginal", "-CreateDate", "-Make", "-Model", str(path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60,
        )
        if result.returncode != 0:
            raise ValueError(result.stderr.strip() or "ExifTool could not read RAW file")
        record = json.loads(result.stdout)[0]
        width = int(record.get("ImageWidth") or 0) or None
        height = int(record.get("ImageHeight") or 0) or None
        if not width or not height:
            raise ValueError("RAW dimensions were not readable")
        return {
            "validation": "valid", "validation_detail": "RAW metadata and dimensions verified",
            "is_image": 1, "width": width, "height": height,
            "megapixels": round(width * height / 1_000_000, 3), "phash": None,
            "exif_date": normalize_exif_date(record.get("DateTimeOriginal") or record.get("CreateDate")),
            "exif_make": record.get("Make"), "exif_model": record.get("Model"),
        }
    except Exception as exc:
        return {
            "validation": "unreadable", "validation_detail": str(exc)[:300], "is_image": 1,
            "width": None, "height": None, "megapixels": None, "phash": None,
            "exif_date": None, "exif_make": None, "exif_model": None,
        }


def categorize(path: Path, metadata: dict) -> tuple[str, int, str]:
    lower = str(path).lower()
    name = path.name.lower()
    width = metadata.get("width") or 0
    height = metadata.get("height") or 0
    make = metadata.get("exif_make")
    model = metadata.get("exif_model")
    if metadata.get("media_kind") == "video":
        return "Videos", 96, "video MIME or extension"
    if any(word in lower for word in THUMB_WORDS) or (width and height and max(width, height) <= 640):
        return "Likely Thumbnails", 82, "thumbnail/cache name or maximum dimension <= 640 px"
    if any(word in name for word in SCREENSHOT_WORDS):
        return "Screenshots", 96, "screenshot naming pattern"
    if make or model or name.startswith(CAMERA_PREFIXES):
        return "Camera Photos", 92 if (make or model) else 78, "camera EXIF or camera filename pattern"
    if any(word in lower for word in DOWNLOAD_WORDS):
        return "Downloads and Messages", 82, "source path or filename pattern"
    if width and height and (width / max(height, 1) > 2.6 or height / max(width, 1) > 2.6):
        return "Graphics and Captures", 65, "unusual aspect ratio and no camera metadata"
    if metadata.get("is_image"):
        return "Uncategorized Images", 40, "image lacks reliable source indicators"
    extension = path.suffix.lower()
    if extension in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf"}:
        return "Documents", 95, "document extension"
    if extension in {".eml", ".msg", ".mbox"}:
        return "Emails", 95, "email extension"
    return "Other Files", 55, "fallback category"


def quality_score(path: Path, metadata: dict) -> float:
    if metadata.get("validation") == "corrupt":
        return -1000.0
    score = 100.0 if metadata.get("validation") == "valid" else 30.0
    pixels = (metadata.get("width") or 0) * (metadata.get("height") or 0)
    if pixels:
        score += math.log10(max(pixels, 1)) * 18
    if metadata.get("exif_date"):
        score += 20
    if metadata.get("exif_make") or metadata.get("exif_model"):
        score += 15
    lower = str(path).lower()
    if any(word in lower for word in THUMB_WORDS):
        score -= 75
    return round(score, 2)


def iter_source_files(
    root: Path, diagnostics: TraversalDiagnostics | None = None,
    directory_callback=None,
):
    """Traverse without materializing every pathname or following directory symlinks."""
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as entries:
                if diagnostics is not None:
                    diagnostics.directories_scanned += 1
                if directory_callback is not None:
                    directory_callback(directory, "available", None)
                for entry in entries:
                    try:
                        if entry.name.casefold() in IGNORED_SYSTEM_DIRECTORIES:
                            if diagnostics is not None:
                                diagnostics.ignored_system_directories += 1
                            if directory_callback is not None:
                                directory_callback(Path(entry.path), "ignored_system", None)
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            yield Path(entry.path)
                    except OSError as exc:
                        if diagnostics is not None:
                            diagnostics.record_error(entry.path, exc)
                        continue
        except OSError as exc:
            if diagnostics is not None:
                diagnostics.record_error(directory, exc)
            if directory_callback is not None:
                directory_callback(directory, "unreadable", exc)
            continue


def analyze_record(record: dict) -> dict:
    """Worker-safe file analysis. Database writes remain in the coordinator thread."""
    path = Path(record["path"])
    extension = record.get("extension") or ""
    mime = sniff_mime(path) if record["size"] else "application/x-empty"
    detected_extension = infer_extension(mime)
    date_proposal = parse_filename_date(path.name)
    media_kind = infer_media_kind(path, mime)
    if record["size"] == 0:
        metadata = {
            "validation": "zero", "validation_detail": "zero-byte file", "is_image": 0,
            "video_analysis_version": VIDEO_ANALYSIS_VERSION if media_kind == "video" else 0,
        }
    elif media_kind == "video":
        metadata = analyze_video(path)
    elif extension in RAW_EXTENSIONS:
        metadata = analyze_raw(path)
    elif extension in IMAGE_EXTENSIONS or mime.startswith("image/"):
        metadata = analyze_image(path)
    else:
        validation, detail = validate_nonimage(path, extension)
        metadata = {"validation": validation, "validation_detail": detail, "is_image": 0}
    metadata["media_kind"] = media_kind
    origin, origin_confidence, origin_reason = infer_media_origin(path, metadata)
    metadata["media_origin"] = origin
    category, category_confidence, category_reason = categorize(path, metadata)
    score = quality_score(path, metadata)
    if not metadata.get("exif_date") and date_proposal.value:
        score += 8
    return {
        "id": record["id"], "mime": mime, "detected_extension": detected_extension,
        **metadata, "filename_date": date_proposal.value, "date_confidence": date_proposal.confidence,
        "date_reason": date_proposal.reason, "category": category,
        "category_confidence": category_confidence, "category_reason": category_reason,
        "media_kind": media_kind, "media_origin": origin,
        "origin_confidence": origin_confidence, "origin_reason": origin_reason,
        "sensitivity": record.get("sensitivity") or "unknown",
        "quality_score": round(score, 2),
    }


class ScanCancelled(Exception):
    pass


class BKTree:
    def __init__(self):
        self.root: tuple[int, dict] | None = None

    @staticmethod
    def distance(left: int, right: int) -> int:
        return (left ^ right).bit_count()

    def add(self, value: int) -> None:
        if self.root is None:
            self.root = (value, {})
            return
        node = self.root
        while True:
            distance = self.distance(value, node[0])
            if distance == 0:
                return
            child = node[1].get(distance)
            if child is None:
                node[1][distance] = (value, {})
                return
            node = child

    def search(self, value: int, radius: int) -> list[int]:
        found: list[int] = []
        if self.root is None:
            return found
        stack = [self.root]
        while stack:
            node = stack.pop()
            distance = self.distance(value, node[0])
            if distance <= radius:
                found.append(node[0])
            low, high = distance - radius, distance + radius
            stack.extend(child for edge, child in node[1].items() if low <= edge <= high)
        return found


class UnionFind:
    def __init__(self):
        self.parent: dict[int, int] = {}

    def find(self, item: int) -> int:
        self.parent.setdefault(item, item)
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, left: int, right: int) -> None:
        a, b = self.find(left), self.find(right)
        if a != b:
            self.parent[b] = a


class Curator:
    def __init__(
        self, source: Path, output: Path, quarantine: Path, db_path: Path,
        allow_actions: bool = False, analysis_workers: int = 2, hash_workers: int = 2,
        batch_size: int = 64, similarity_radius: int = 6,
        reference_root: Path | None = None,
        output_uid: int | None = None, output_gid: int | None = None,
    ):
        self.source = source.resolve()
        self.output = output.resolve()
        self.quarantine = quarantine.resolve()
        self.db_path = db_path
        self.reference_root = reference_root.resolve() if reference_root else None
        self.output_uid = os.geteuid() if output_uid is None else int(output_uid)
        self.output_gid = os.getegid() if output_gid is None else int(output_gid)
        self.allow_actions = allow_actions
        self.analysis_workers = max(1, min(int(analysis_workers), 8))
        self.hash_workers = max(1, min(int(hash_workers), 8))
        self.batch_size = max(8, min(int(batch_size), 1000))
        self.similarity_radius = max(0, min(int(similarity_radius), 16))
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.phase_started = time.monotonic()
        self.state = {
            "running": False, "phase": "idle", "processed": 0, "total": 0,
            "rate": 0.0, "message": "Ready", "error": None,
        }
        initialize(db_path)

    def status(self) -> dict:
        with self.lock:
            return dict(self.state)

    def source_diagnostic(self) -> dict:
        result = {
            "path": str(self.source), "exists": self.source.exists(),
            "is_directory": self.source.is_dir(), "readable": False,
            "has_entries": False, "error": None,
        }
        if not result["is_directory"]:
            result["error"] = "The recovered-source mount is missing or is not a directory."
            return result
        try:
            with os.scandir(self.source) as entries:
                result["has_entries"] = next(entries, None) is not None
            result["readable"] = True
        except OSError as exc:
            result["error"] = str(exc)
        return result

    def switch_database(self, db_path: Path) -> None:
        with self.lock:
            if self.state["running"]:
                raise RuntimeError("Cancel the active scan and wait for it to stop before switching saved scans.")
            self.db_path = db_path
            initialize(self.db_path)
            self.stop_event.clear()
            self.state.update(
                running=False, phase="idle", processed=0, total=0, rate=0.0,
                message="Saved scan loaded", error=None,
            )

    def _set_state(self, **values) -> None:
        with self.lock:
            self.state.update(values)

    def _begin_phase(self, phase: str, total: int, message: str) -> None:
        self.phase_started = time.monotonic()
        self._set_state(phase=phase, total=total, processed=0, rate=0.0, message=message)

    def _progress(self, processed: int, total: int | None = None, message: str | None = None) -> None:
        elapsed = max(time.monotonic() - self.phase_started, 0.001)
        values = {"processed": processed, "rate": round(processed / elapsed, 2)}
        if total is not None:
            values["total"] = total
        if message is not None:
            values["message"] = message
        self._set_state(**values)

    def _check_cancel(self) -> None:
        if self.stop_event.is_set():
            raise ScanCancelled("Scan stopped after the latest completed checkpoint")

    def start_scan(self) -> bool:
        with self.lock:
            if self.state["running"]:
                return False
            self.state.update(running=True, phase="inventory", processed=0, total=0, rate=0.0, message="Starting scan", error=None)
        self.stop_event.clear()
        threading.Thread(target=self._scan_wrapper, daemon=True).start()
        return True

    def request_stop(self) -> bool:
        if not self.status()["running"]:
            return False
        self.stop_event.set()
        self._set_state(message="Stopping after the current batch checkpoint…")
        return True

    def reset_catalog(self) -> dict:
        """Remove scan state and generated reports without touching any library files."""
        with self.lock:
            if self.state["running"]:
                raise RuntimeError("Cancel the active scan and wait for it to stop before clearing the catalog.")
        with connect(self.db_path) as db:
            file_count = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
            reference_count = db.execute("SELECT COUNT(*) FROM reference_files").fetchone()[0]
            directory_count = db.execute("SELECT COUNT(*) FROM directories").fetchone()[0]
            db.execute("DELETE FROM actions")
            db.execute("DELETE FROM ai_runs")
            db.execute("DELETE FROM ai_structure_suggestions")
            db.execute("DELETE FROM review_questions")
            db.execute("DELETE FROM ai_provider_settings")
            db.execute("DELETE FROM reconstruction_proposals")
            db.execute("DELETE FROM reconstruction_directories")
            db.execute("DELETE FROM file_relationships")
            db.execute("DELETE FROM file_facets")
            db.execute("DELETE FROM known_good_matches")
            db.execute("DELETE FROM folder_context")
            db.execute("DELETE FROM recovery_context")
            db.execute("DELETE FROM files")
            db.execute("DELETE FROM directories")
            db.execute("DELETE FROM reference_files")
            db.execute("DELETE FROM settings")
            db.commit()
        try:
            self._ai_secret_path().unlink()
        except FileNotFoundError:
            pass
        removed_reports = 0
        for name in (
            "recovery_catalog.csv", "recovery_catalog.jsonl",
            "directory_catalog.csv", "directory_catalog.jsonl",
            "reconstruction_plan.csv", "reconstruction_plan.jsonl",
            "reconstruction_directories.csv", "reconstruction_directories.jsonl",
            "folder_context.csv", "folder_context.jsonl",
            "known_good_matches.csv", "known_good_matches.jsonl",
            "file_relationships.csv", "file_relationships.jsonl",
            "file_facets.csv", "file_facets.jsonl",
            "recovery_context.csv", "recovery_context.jsonl",
            "review_questions.csv", "review_questions.jsonl",
            "ai_structure_suggestions.csv", "ai_structure_suggestions.jsonl",
        ):
            report = self.db_path.parent / name
            try:
                report.unlink()
                removed_reports += 1
            except FileNotFoundError:
                pass
        self.stop_event.clear()
        self._set_state(
            running=False, phase="idle", processed=0, total=0, rate=0.0,
            message="Catalog cleared. Ready for a new scan.", error=None,
        )
        return {
            "files": file_count, "directories": directory_count,
            "reference_files": reference_count, "reports": removed_reports,
        }

    @staticmethod
    def _paths_overlap(left: Path, right: Path) -> bool:
        return left == right or left in right.parents or right in left.parents

    def _selected_reference_values(self, db: sqlite3.Connection | None = None) -> list[str]:
        owns_connection = db is None
        connection = db or connect(self.db_path)
        try:
            row = connection.execute("SELECT value FROM settings WHERE key='reference_selections'").fetchone()
            if not row:
                return []
            values = json.loads(row["value"])
            return sorted({str(value) for value in values if isinstance(value, str)})
        except (TypeError, ValueError, json.JSONDecodeError):
            return []
        finally:
            if owns_connection:
                connection.close()

    def _normalize_reference_relative(self, relative: str, require_exists: bool = True) -> tuple[str, Path]:
        if self.reference_root is None:
            raise ValueError("Configure the Known-Good Root path in the Unraid container first.")
        requested = Path(relative or ".")
        if requested.is_absolute():
            raise ValueError("Known-good selections must stay inside the configured root.")
        candidate = (self.reference_root / requested).resolve()
        if candidate != self.reference_root and self.reference_root not in candidate.parents:
            raise ValueError("Known-good selections must stay inside the configured root.")
        if require_exists and (not candidate.exists() or not candidate.is_dir()):
            raise FileNotFoundError("The selected known-good folder does not exist or is not a directory.")
        normalized = "." if candidate == self.reference_root else candidate.relative_to(self.reference_root).as_posix()
        return normalized, candidate

    def selected_references(self) -> list[dict]:
        selections = []
        for relative in self._selected_reference_values():
            try:
                normalized, path = self._normalize_reference_relative(relative, require_exists=False)
            except ValueError:
                continue
            selections.append({"relative": normalized, "path": str(path), "available": path.is_dir()})
        return selections

    def browse_reference_directories(self, relative: str = ".") -> dict:
        current_relative, current = self._normalize_reference_relative(relative)
        directories = []
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if not entry.is_dir(follow_symlinks=False):
                            continue
                        child = Path(entry.path).resolve()
                        if child != self.reference_root and self.reference_root not in child.parents:
                            continue
                        directories.append({
                            "name": entry.name,
                            "relative": child.relative_to(self.reference_root).as_posix(),
                        })
                    except OSError:
                        continue
        except OSError as exc:
            raise OSError(f"Unable to browse known-good folder: {exc}") from exc
        directories.sort(key=lambda item: item["name"].casefold())
        if current == self.reference_root:
            parent = None
        else:
            parent_path = current.parent
            parent = "." if parent_path == self.reference_root else parent_path.relative_to(self.reference_root).as_posix()
        return {
            "current": current_relative, "current_path": str(current), "parent": parent,
            "directories": directories, "selected": self.selected_references(),
        }

    def add_reference_selection(self, relative: str) -> str:
        normalized, candidate = self._normalize_reference_relative(relative)
        selections = self._selected_reference_values()
        for existing in selections:
            existing_normalized, existing_path = self._normalize_reference_relative(existing, require_exists=False)
            if existing_normalized == normalized:
                return normalized
            if self._paths_overlap(existing_path, candidate):
                raise ValueError("That folder overlaps an existing selection. Remove the existing selection first.")
        selections.append(normalized)
        with connect(self.db_path) as db:
            db.execute(
                "INSERT INTO settings(key,value) VALUES('reference_selections',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (json.dumps(sorted(selections)),),
            )
            db.commit()
        return normalized

    def remove_reference_selection(self, relative: str) -> None:
        normalized, _ = self._normalize_reference_relative(relative, require_exists=False)
        selections = [value for value in self._selected_reference_values() if value != normalized]
        with connect(self.db_path) as db:
            db.execute(
                "INSERT INTO settings(key,value) VALUES('reference_selections',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (json.dumps(selections),),
            )
            db.execute("DELETE FROM reference_files WHERE library=?", (normalized,))
            self._mark_known_good_matches(db, update_progress=False)
            db.commit()

    def _configured_reference_roots(self, db: sqlite3.Connection | None = None) -> list[tuple[str, Path]]:
        configured = []
        for relative in self._selected_reference_values(db):
            try:
                normalized, path = self._normalize_reference_relative(relative, require_exists=False)
            except ValueError:
                continue
            configured.append((normalized, path))
        return configured

    def _validate_reference_roots(self) -> None:
        existing = [(label, root) for label, root in self._configured_reference_roots() if root.exists()]
        for label, root in existing:
            if self._paths_overlap(self.source, root):
                raise ValueError(f"{label} overlaps the recovered source; reference libraries must be separate read-only folders.")
        for index, (left_label, left_root) in enumerate(existing):
            for right_label, right_root in existing[index + 1:]:
                if self._paths_overlap(left_root, right_root):
                    raise ValueError(f"{left_label} and {right_label} overlap; mount each known-good library only once.")

    def _scan_wrapper(self) -> None:
        try:
            result = self.scan()
            warning_count = result.get("source_read_errors", 0)
            message = "Scan complete"
            if warning_count:
                message = (
                    f"Scan complete with {warning_count:,} recovered-source read warning(s). "
                    "Readable files were processed and older unseen catalog entries were retained."
                )
            self._set_state(running=False, phase="complete", message=message)
        except ScanCancelled as exc:
            self._set_state(running=False, phase="stopped", message=str(exc), error=None)
        except Exception as exc:
            self._set_state(running=False, phase="failed", message="Scan failed", error=str(exc))

    def scan(self) -> dict:
        source_diagnostic = self.source_diagnostic()
        if not source_diagnostic["is_directory"]:
            raise FileNotFoundError(
                f"Recovered Source is not mounted as a directory at {self.source}. "
                "Check the Recovered Source host-path mapping in the Unraid container."
            )
        if not source_diagnostic["readable"]:
            raise PermissionError(
                f"Recovered Source cannot be read at {self.source}: {source_diagnostic['error']}. "
                "Check the container path permissions."
            )
        self._validate_reference_roots()
        scan_token = utcnow() + "-" + os.urandom(4).hex()
        self._begin_phase("inventory", 0, "Inventorying files with bounded memory")
        with connect(self.db_path) as db:
            inventory_count = 0
            traversal = TraversalDiagnostics()

            def record_directory(path: Path, status: str, error: OSError | None) -> None:
                try:
                    stat = path.stat()
                except OSError:
                    stat = None
                relative = "." if path == self.source else path.relative_to(self.source).as_posix()
                parent = None if relative == "." else (Path(relative).parent.as_posix() or ".")
                db.execute(
                    """INSERT INTO directories(
                         path,relative_path,parent_relative_path,name,mtime_ns,ctime_ns,mode,uid,gid,
                         status,read_error,seen_scan,updated_at
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(path) DO UPDATE SET
                         relative_path=excluded.relative_path,parent_relative_path=excluded.parent_relative_path,
                         name=excluded.name,mtime_ns=excluded.mtime_ns,ctime_ns=excluded.ctime_ns,
                         mode=excluded.mode,uid=excluded.uid,gid=excluded.gid,status=excluded.status,
                         read_error=excluded.read_error,seen_scan=excluded.seen_scan,updated_at=excluded.updated_at""",
                    (
                        str(path), relative, parent, path.name,
                        stat.st_mtime_ns if stat else None, stat.st_ctime_ns if stat else None,
                        stat_module.S_IMODE(stat.st_mode) if stat else None,
                        stat.st_uid if stat else None, stat.st_gid if stat else None,
                        status, str(error)[:500] if error else None, scan_token, utcnow(),
                    ),
                )

            for index, path in enumerate(
                iter_source_files(self.source, traversal, directory_callback=record_directory), 1
            ):
                try:
                    stat = path.stat()
                except OSError as exc:
                    traversal.record_error(path, exc)
                    continue
                inventory_count = index
                relative = str(path.relative_to(self.source))
                existing = db.execute("SELECT size,mtime_ns FROM files WHERE path=?", (str(path),)).fetchone()
                changed = not existing or existing["size"] != stat.st_size or existing["mtime_ns"] != stat.st_mtime_ns
                db.execute(
                    """INSERT INTO files(
                         path,relative_path,name,extension,size,mtime_ns,ctime_ns,mode,uid,gid,seen_scan,updated_at
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(path) DO UPDATE SET relative_path=excluded.relative_path,name=excluded.name,
                         extension=excluded.extension,size=excluded.size,mtime_ns=excluded.mtime_ns,
                         ctime_ns=excluded.ctime_ns,mode=excluded.mode,uid=excluded.uid,gid=excluded.gid,
                         seen_scan=excluded.seen_scan,updated_at=excluded.updated_at""",
                    (
                        str(path), relative, path.name, path.suffix.lower(), stat.st_size, stat.st_mtime_ns,
                        stat.st_ctime_ns, stat_module.S_IMODE(stat.st_mode), stat.st_uid, stat.st_gid,
                        scan_token, utcnow(),
                    ),
                )
                if changed:
                    db.execute(
                        """UPDATE files SET mime=NULL,detected_extension=NULL,validation='unchecked',validation_detail=NULL,
                           content_hash=NULL,is_image=0,width=NULL,height=NULL,megapixels=NULL,phash=NULL,exif_date=NULL,
                           exif_make=NULL,exif_model=NULL,filename_date=NULL,date_confidence=0,date_reason=NULL,
                           category=NULL,category_confidence=0,category_reason=NULL,quality_score=0,exact_group=NULL,
                           similar_group=NULL,known_good_match=0,known_good_count=0,known_good_library=NULL,
                           known_good_path=NULL,decision='undecided',exported_path=NULL,ai_caption=NULL,ai_people=NULL,
                           ai_objects=NULL,ai_ocr_text=NULL,ai_tags=NULL,ai_model=NULL,ai_updated_at=NULL,
                           media_kind='other',media_origin='unknown',sensitivity='unknown',video_duration=NULL,
                           video_width=NULL,video_height=NULL,video_fps=NULL,video_codec=NULL,audio_codec=NULL,
                           video_creation_date=NULL,video_analysis_version=0 WHERE path=?""", (str(path),)
                    )
                if index % self.batch_size == 0:
                    db.commit()
                    self._progress(index, index, f"Inventorying files — {index:,} found")
                    self._check_cancel()
            if inventory_count == 0:
                raise RuntimeError(
                    f"No recovered files are visible under {self.source}. The scan was stopped before "
                    "known-good indexing and the existing catalog was retained. Check the Recovered Source "
                    "host path in the Unraid container; Recovery Curator does not follow directory symlinks."
                )
            inventory_result = {
                "completed_at": utcnow(),
                "files_seen": inventory_count,
                "directories_scanned": traversal.directories_scanned,
                "source_read_errors": traversal.errors,
                "first_source_error": traversal.first_error,
                "ignored_system_directories": traversal.ignored_system_directories,
                "removed_missing_records": traversal.errors == 0,
            }
            db.execute(
                "INSERT INTO settings(key,value) VALUES('last_source_inventory',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (json.dumps(inventory_result),),
            )
            if traversal.errors == 0:
                db.execute("DELETE FROM files WHERE seen_scan IS NULL OR seen_scan != ?", (scan_token,))
                db.execute("DELETE FROM directories WHERE seen_scan IS NULL OR seen_scan != ?", (scan_token,))
            db.commit()
            inventory_message = f"Inventory complete — {inventory_count:,} files"
            if traversal.ignored_system_directories:
                inventory_message += f"; skipped {traversal.ignored_system_directories:,} Windows system folder(s)"
            if traversal.errors:
                inventory_message += f"; {traversal.errors:,} read warning(s)"
            self._progress(inventory_count, inventory_count, inventory_message)

            self._analyze_pending(db)
            self._inventory_references(db)
            self._hash_reference_candidates(db)
            self._hash_candidates(db)
            self._mark_known_good_matches(db)
            db.execute("UPDATE files SET exact_group=NULL")
            db.execute(
                """UPDATE files SET exact_group=content_hash WHERE content_hash IN
                   (SELECT content_hash FROM files WHERE content_hash IS NOT NULL GROUP BY content_hash HAVING COUNT(*)>1)"""
            )
            db.commit()

        self._build_similar_groups(self.similarity_radius)
        self.export_catalog()
        self.export_directory_catalog()
        return inventory_result

    def _analyze_pending(self, db: sqlite3.Connection) -> None:
        pending_where = "mime IS NULL OR (media_kind='video' AND COALESCE(video_analysis_version,0)<?)"
        total = db.execute(f"SELECT COUNT(*) FROM files WHERE {pending_where}", (VIDEO_ANALYSIS_VERSION,)).fetchone()[0]
        self._begin_phase(
            "analysis", total,
            f"Validating and classifying files with {self.analysis_workers} worker(s)",
        )
        processed = 0
        while True:
            self._check_cancel()
            rows = [dict(row) for row in db.execute(
                f"SELECT * FROM files WHERE {pending_where} ORDER BY id LIMIT ?",
                (VIDEO_ANALYSIS_VERSION, self.batch_size),
            ).fetchall()]
            if not rows:
                break
            with ThreadPoolExecutor(max_workers=self.analysis_workers, thread_name_prefix="analyze") as pool:
                futures = {pool.submit(analyze_record, row): row for row in rows}
                for future in as_completed(futures):
                    source_row = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "id": source_row["id"], "mime": "application/octet-stream", "detected_extension": None,
                            "validation": "unreadable", "validation_detail": str(exc)[:300], "is_image": 0,
                            "width": None, "height": None, "megapixels": None, "phash": None, "exif_date": None,
                            "exif_make": None, "exif_model": None, "filename_date": None, "date_confidence": 0,
                            "date_reason": "analysis failed", "category": "Other Files", "category_confidence": 0,
                            "category_reason": "analysis failed", "quality_score": -1000,
                            "media_kind": infer_media_kind(Path(source_row["path"]), source_row.get("mime")),
                            "media_origin": "unknown", "sensitivity": source_row.get("sensitivity") or "unknown",
                            "video_duration": None, "video_width": None, "video_height": None, "video_fps": None,
                            "video_codec": None, "audio_codec": None, "video_creation_date": None,
                            "video_analysis_version": VIDEO_ANALYSIS_VERSION,
                        }
                    db.execute(
                        """UPDATE files SET mime=?,detected_extension=?,validation=?,validation_detail=?,is_image=?,
                           width=?,height=?,megapixels=?,phash=?,exif_date=?,exif_make=?,exif_model=?,filename_date=?,
                           date_confidence=?,date_reason=?,category=?,category_confidence=?,category_reason=?,quality_score=?,
                           media_kind=?,media_origin=?,sensitivity=?,video_duration=?,video_width=?,video_height=?,video_fps=?,
                           video_codec=?,audio_codec=?,video_creation_date=?,video_analysis_version=?,updated_at=?
                           WHERE id=?""",
                        (result["mime"], result["detected_extension"], result.get("validation"), result.get("validation_detail"),
                         result.get("is_image", 0), result.get("width"), result.get("height"), result.get("megapixels"),
                         result.get("phash"), result.get("exif_date"), result.get("exif_make"), result.get("exif_model"),
                         result.get("filename_date"), result.get("date_confidence", 0), result.get("date_reason"),
                         result.get("category"), result.get("category_confidence", 0), result.get("category_reason"),
                         result.get("quality_score", 0), result.get("media_kind", "other"),
                         result.get("media_origin", "unknown"), result.get("sensitivity", "unknown"),
                         result.get("video_duration"), result.get("video_width"), result.get("video_height"),
                         result.get("video_fps"), result.get("video_codec"), result.get("audio_codec"),
                         result.get("video_creation_date"), result.get("video_analysis_version", 0), utcnow(), result["id"]),
                    )
                    db.execute("DELETE FROM file_facets WHERE file_id=? AND source='deterministic'", (result["id"],))
                    facets = [
                        (result["id"], "media_type", result.get("media_kind", "other"), 100, "deterministic", "MIME or extension", utcnow()),
                        (result["id"], "origin", result.get("media_origin", "unknown"), result.get("origin_confidence", 0),
                         "deterministic", result.get("origin_reason"), utcnow()),
                    ]
                    db.executemany(
                        """INSERT OR REPLACE INTO file_facets(
                             file_id,facet_type,value,confidence,source,reason,updated_at
                           ) VALUES(?,?,?,?,?,?,?)""",
                        facets,
                    )
            db.commit()
            processed += len(rows)
            self._progress(processed, total)

    def _inventory_references(self, db: sqlite3.Connection) -> None:
        configured_roots = self._configured_reference_roots(db)
        configured_labels = {label for label, _ in configured_roots}
        if configured_labels:
            placeholders = ",".join("?" for _ in configured_labels)
            db.execute(f"DELETE FROM reference_files WHERE library NOT IN ({placeholders})", tuple(configured_labels))
        else:
            db.execute("DELETE FROM reference_files")
            db.execute(
                "UPDATE files SET known_good_match=0,known_good_count=0,known_good_library=NULL,known_good_path=NULL"
            )
            db.commit()
            return

        for label, root in configured_roots:
            if not root.exists() or not root.is_dir():
                db.execute("DELETE FROM reference_files WHERE library=?", (label,))
                db.commit()
                continue
            scan_token = utcnow() + "-" + os.urandom(4).hex()
            self._begin_phase("reference_inventory", 0, f"Inventorying {label}")
            inventory_count = 0
            for index, path in enumerate(iter_source_files(root), 1):
                try:
                    stat = path.stat()
                except OSError:
                    continue
                inventory_count = index
                relative = str(path.relative_to(root))
                existing = db.execute(
                    "SELECT size,mtime_ns,library FROM reference_files WHERE path=?", (str(path),)
                ).fetchone()
                changed = (
                    not existing or existing["size"] != stat.st_size or
                    existing["mtime_ns"] != stat.st_mtime_ns or existing["library"] != label
                )
                db.execute(
                    """INSERT INTO reference_files(library,path,relative_path,size,mtime_ns,seen_scan,updated_at)
                       VALUES(?,?,?,?,?,?,?)
                       ON CONFLICT(path) DO UPDATE SET library=excluded.library,relative_path=excluded.relative_path,
                         size=excluded.size,mtime_ns=excluded.mtime_ns,seen_scan=excluded.seen_scan,
                         updated_at=excluded.updated_at""",
                    (label, str(path), relative, stat.st_size, stat.st_mtime_ns, scan_token, utcnow()),
                )
                if changed:
                    db.execute(
                        "UPDATE reference_files SET content_hash=NULL,hash_error=NULL WHERE path=?", (str(path),)
                    )
                if index % self.batch_size == 0:
                    db.commit()
                    self._progress(index, index, f"Inventorying {label} — {index:,} files found")
                    self._check_cancel()
            db.execute(
                "DELETE FROM reference_files WHERE library=? AND (seen_scan IS NULL OR seen_scan != ?)",
                (label, scan_token),
            )
            db.commit()
            self._progress(inventory_count, inventory_count, f"{label} inventory complete — {inventory_count:,} files")

    def _hash_reference_candidates(self, db: sqlite3.Connection) -> None:
        candidate_where = """r.size>0 AND r.content_hash IS NULL AND r.hash_error IS NULL AND
                             EXISTS(SELECT 1 FROM files f WHERE f.size=r.size)"""
        total = db.execute(f"SELECT COUNT(*) FROM reference_files r WHERE {candidate_where}").fetchone()[0]
        self._begin_phase(
            "reference_hashing", total,
            f"Hashing known-good files with recovery size matches using {self.hash_workers} worker(s)",
        )
        processed = 0
        while True:
            self._check_cancel()
            rows = [dict(row) for row in db.execute(
                f"SELECT r.id,r.path FROM reference_files r WHERE {candidate_where} ORDER BY r.id LIMIT ?",
                (self.batch_size,),
            ).fetchall()]
            if not rows:
                break
            with ThreadPoolExecutor(max_workers=self.hash_workers, thread_name_prefix="reference-hash") as pool:
                futures = {pool.submit(file_blake3, Path(row["path"])): row for row in rows}
                for future in as_completed(futures):
                    row = futures[future]
                    try:
                        digest = future.result()
                    except Exception as exc:
                        db.execute(
                            "UPDATE reference_files SET hash_error=? WHERE id=?", (str(exc)[:300], row["id"])
                        )
                    else:
                        db.execute(
                            "UPDATE reference_files SET content_hash=?,hash_error=NULL WHERE id=?", (digest, row["id"])
                        )
            db.commit()
            processed += len(rows)
            self._progress(processed, total)

    def _hash_candidates(self, db: sqlite3.Connection) -> None:
        candidate_join = """JOIN (
                              SELECT size FROM files WHERE size>0 GROUP BY size HAVING COUNT(*)>1
                              UNION
                              SELECT DISTINCT size FROM reference_files WHERE size>0 AND content_hash IS NOT NULL
                            ) d ON d.size=f.size"""
        total = db.execute(
            f"SELECT COUNT(*) FROM files f {candidate_join} WHERE f.content_hash IS NULL"
        ).fetchone()[0]
        self._begin_phase(
            "hashing", total,
            f"Hashing size-matched duplicate candidates with {self.hash_workers} worker(s)",
        )
        processed = 0
        while True:
            self._check_cancel()
            rows = [dict(row) for row in db.execute(
                f"SELECT f.id,f.path FROM files f {candidate_join} WHERE f.content_hash IS NULL ORDER BY f.id LIMIT ?",
                (self.batch_size,),
            ).fetchall()]
            if not rows:
                break
            with ThreadPoolExecutor(max_workers=self.hash_workers, thread_name_prefix="hash") as pool:
                futures = {pool.submit(file_blake3, Path(row["path"])): row for row in rows}
                for future in as_completed(futures):
                    row = futures[future]
                    try:
                        digest = future.result()
                    except OSError as exc:
                        db.execute(
                            "UPDATE files SET validation='unreadable',validation_detail=?,content_hash=? WHERE id=?",
                            (str(exc)[:300], f"ERROR:{row['id']}", row["id"]),
                        )
                    except Exception as exc:
                        db.execute(
                            "UPDATE files SET validation='unreadable',validation_detail=?,content_hash=? WHERE id=?",
                            (str(exc)[:300], f"ERROR:{row['id']}", row["id"]),
                        )
                    else:
                        db.execute("UPDATE files SET content_hash=? WHERE id=?", (digest, row["id"]))
            db.commit()
            processed += len(rows)
            self._progress(processed, total)

    def _mark_known_good_matches(self, db: sqlite3.Connection, update_progress: bool = True) -> None:
        if update_progress:
            self._begin_phase("known_good_matching", 1, "Matching recovery hashes against known-good libraries")
        db.execute(
            "UPDATE files SET known_good_match=0,known_good_count=0,known_good_library=NULL,known_good_path=NULL"
        )
        db.execute("DELETE FROM known_good_matches")
        db.execute(
            """UPDATE files SET
                 known_good_match=1,
                 known_good_count=(SELECT COUNT(*) FROM reference_files r
                                   WHERE r.size=files.size AND r.content_hash=files.content_hash),
                 known_good_library=(SELECT r.library FROM reference_files r
                                     WHERE r.size=files.size AND r.content_hash=files.content_hash
                                     ORDER BY r.library,r.path LIMIT 1),
                 known_good_path=(SELECT r.path FROM reference_files r
                                  WHERE r.size=files.size AND r.content_hash=files.content_hash
                                  ORDER BY r.library,r.path LIMIT 1)
               WHERE files.content_hash IS NOT NULL AND files.content_hash NOT LIKE 'ERROR:%'
                 AND EXISTS(SELECT 1 FROM reference_files r
                            WHERE r.size=files.size AND r.content_hash=files.content_hash)"""
        )
        db.execute(
            """INSERT INTO known_good_matches(
                 file_id,reference_file_id,library,relative_path,confidence,updated_at
               )
               SELECT f.id,r.id,r.library,r.relative_path,100,?
               FROM files f JOIN reference_files r
                 ON r.size=f.size AND r.content_hash=f.content_hash
               WHERE f.content_hash IS NOT NULL AND f.content_hash NOT LIKE 'ERROR:%'""",
            (utcnow(),),
        )
        db.commit()
        matches = db.execute("SELECT COUNT(*) FROM files WHERE known_good_match=1").fetchone()[0]
        if update_progress:
            self._progress(1, 1, f"Known-good comparison complete — {matches:,} exact matches")

    def start_reconstruction(self) -> bool:
        with self.lock:
            if self.state["running"]:
                return False
            self.state.update(
                running=True, phase="reconstruction", processed=0, total=0, rate=0.0,
                message="Starting media enrichment and reconstruction planning", error=None,
            )
        self.stop_event.clear()
        threading.Thread(target=self._reconstruction_wrapper, daemon=True).start()
        return True

    def _reconstruction_wrapper(self) -> None:
        try:
            result = self.build_reconstruction_foundation()
            self._set_state(
                running=False, phase="complete",
                message=(
                    f"Reconstruction plan ready — {result['proposals']:,} proposals, "
                    f"{result['folder_suggestions']:,} discovered folders"
                ),
                error=None,
            )
        except ScanCancelled as exc:
            self._set_state(running=False, phase="stopped", message=str(exc), error=None)
        except Exception as exc:
            self._set_state(running=False, phase="failed", message="Reconstruction analysis failed", error=str(exc))

    def build_reconstruction_foundation(self) -> dict:
        with connect(self.db_path) as db:
            if db.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0:
                raise RuntimeError("Run a recovery scan before building a reconstruction plan.")
            self._analyze_pending(db)
            self._check_cancel()
            self._begin_phase("facets", 1, "Deriving media types, origins, and deterministic tags")
            self._backfill_facets(db)
            self._progress(1, 1)
            self._check_cancel()
            self._refresh_known_good_relationships(db)
            self._build_placeholder_relationships(db)
            self._refresh_folder_context(db)
            self._build_reconstruction_proposals(db)
            db.commit()
        self.export_catalog()
        self.export_reconstruction_catalogs()
        return self.reconstruction_summary()

    def _backfill_facets(self, db: sqlite3.Connection) -> None:
        video_extensions = tuple(sorted(VIDEO_EXTENSIONS))
        image_extensions = tuple(sorted(IMAGE_EXTENSIONS | RAW_EXTENSIONS))
        video_marks = ",".join("?" for _ in video_extensions)
        image_marks = ",".join("?" for _ in image_extensions)
        db.execute(
            f"UPDATE files SET media_kind='video' WHERE lower(extension) IN ({video_marks}) OR mime LIKE 'video/%'",
            video_extensions,
        )
        db.execute(
            f"UPDATE files SET media_kind='photo' WHERE is_image=1 OR lower(extension) IN ({image_marks}) OR mime LIKE 'image/%'",
            image_extensions,
        )
        db.execute("UPDATE files SET media_kind='document' WHERE category='Documents'")
        db.execute("UPDATE files SET media_kind='email' WHERE category='Emails'")
        db.execute("UPDATE files SET media_kind='audio' WHERE mime LIKE 'audio/%'")
        db.execute(
            """UPDATE files SET category='Videos',category_confidence=96,
                   category_reason='video MIME or extension' WHERE media_kind='video'"""
        )
        db.execute(
            """UPDATE files SET media_origin='snapchat'
               WHERE lower(path) LIKE '%snapchat%' OR lower(path) LIKE '%snapsave%'"""
        )
        db.execute(
            """UPDATE files SET media_origin='screen_recording'
               WHERE lower(name) LIKE '%screenrecord%' OR lower(name) LIKE '%screen recording%'"""
        )
        db.execute(
            """UPDATE files SET media_origin='screenshot'
               WHERE media_origin='unknown' AND (
                 lower(name) LIKE '%screenshot%' OR lower(name) LIKE '%screen shot%' OR lower(name) LIKE '%screencap%'
               )"""
        )
        db.execute(
            """UPDATE files SET media_origin='downloaded'
               WHERE media_origin='unknown' AND (
                 lower(path) LIKE '%download%' OR lower(path) LIKE '%messenger%' OR lower(path) LIKE '%whatsapp%'
                 OR lower(path) LIKE '%telegram%' OR lower(path) LIKE '%wallpaper%' OR lower(path) LIKE '%background%'
               )"""
        )
        db.execute(
            """UPDATE files SET media_origin='camera'
               WHERE media_origin='unknown' AND (
                 exif_make IS NOT NULL OR exif_model IS NOT NULL OR lower(name) GLOB 'img_*'
                 OR lower(name) GLOB 'dsc_*' OR lower(name) GLOB 'pxl_*'
               )"""
        )
        now = utcnow()
        db.execute("DELETE FROM file_facets WHERE source='deterministic'")
        db.execute(
            """INSERT INTO file_facets(file_id,facet_type,value,confidence,source,reason,updated_at)
               SELECT id,'media_type',COALESCE(media_kind,'other'),100,'deterministic','MIME, extension, or validated format',?
               FROM files""",
            (now,),
        )
        db.execute(
            """INSERT INTO file_facets(file_id,facet_type,value,confidence,source,reason,updated_at)
               SELECT id,'origin',media_origin,
                      CASE media_origin WHEN 'snapchat' THEN 94 WHEN 'screenshot' THEN 96
                           WHEN 'screen_recording' THEN 94 WHEN 'camera' THEN 82
                           WHEN 'downloaded' THEN 75 ELSE 0 END,
                      'deterministic','path, filename, or embedded metadata',?
               FROM files WHERE media_origin!='unknown'""",
            (now,),
        )
        topic_rules = (
            ("space_nasa", "%nasa%", "NASA path/name"),
            ("space_jwst", "%jwst%", "JWST path/name"),
            ("background_wallpaper", "%wallpaper%", "wallpaper path/name"),
        )
        for value, pattern, reason in topic_rules:
            db.execute(
                """INSERT OR IGNORE INTO file_facets(
                     file_id,facet_type,value,confidence,source,reason,updated_at
                   ) SELECT id,'topic',?,80,'deterministic',?,? FROM files WHERE lower(path) LIKE ?""",
                (value, reason, now, pattern),
            )
        db.commit()

    def _refresh_known_good_relationships(self, db: sqlite3.Connection) -> None:
        self._begin_phase("known_good_relationships", 1, "Preserving every known-good path relationship")
        self._mark_known_good_matches(db, update_progress=False)
        db.commit()
        self._progress(1, 1)

    def _build_placeholder_relationships(self, db: sqlite3.Connection) -> None:
        total = db.execute("SELECT COUNT(*) FROM files WHERE size=0").fetchone()[0]
        self._begin_phase(
            "placeholder_index",
            1,
            "Indexing filenames for zero-byte placeholder matching",
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_files_name_nocase_size "
            "ON files(name COLLATE NOCASE,size)"
        )
        db.execute("DELETE FROM file_relationships WHERE relationship='zero_same_name'")
        db.execute("DROP TABLE IF EXISTS temp.placeholder_candidates")
        db.execute(
            """CREATE TEMP TABLE placeholder_candidates(
                 name_key TEXT PRIMARY KEY COLLATE NOCASE,
                 candidate_count INTEGER NOT NULL,
                 hash_count INTEGER NOT NULL
               ) WITHOUT ROWID"""
        )
        db.execute(
            """INSERT INTO placeholder_candidates(name_key,candidate_count,hash_count)
               SELECT MIN(name),COUNT(*),COUNT(DISTINCT content_hash)
               FROM files
               WHERE size>0
               GROUP BY name COLLATE NOCASE
               HAVING COUNT(*)<=10"""
        )
        db.commit()
        self._progress(1, 1)

        self._begin_phase(
            "placeholder_relationships",
            total,
            f"Linking {total:,} zero-byte placeholders to surviving content",
        )
        processed = 0
        last_id = 0
        try:
            while True:
                self._check_cancel()
                rows = db.execute(
                    "SELECT id FROM files WHERE size=0 AND id>? ORDER BY id LIMIT ?",
                    (last_id, self.batch_size),
                ).fetchall()
                if not rows:
                    break
                ids = [int(row["id"]) for row in rows]
                markers = ",".join("?" for _ in ids)
                db.execute(
                    f"""INSERT OR IGNORE INTO file_relationships(
                           file_id,related_file_id,relationship,confidence,evidence,updated_at
                         )
                         SELECT z.id,n.id,'zero_same_name',
                                CASE WHEN c.hash_count=1 THEN 92
                                     WHEN c.candidate_count=1 THEN 85 ELSE 55 END,
                                json_object(
                                  'filename',z.name,
                                  'candidate_count',c.candidate_count,
                                  'hash_count',c.hash_count
                                ),?
                         FROM files z
                         JOIN placeholder_candidates c
                           ON c.name_key=z.name COLLATE NOCASE
                         JOIN files n
                           ON n.name=c.name_key COLLATE NOCASE AND n.size>0
                         WHERE z.id IN ({markers})""",
                    (utcnow(), *ids),
                )
                db.commit()
                last_id = ids[-1]
                processed += len(ids)
                self._progress(
                    processed,
                    total,
                    f"Linking zero-byte placeholders — {processed:,}/{total:,}",
                )
        finally:
            db.execute("DROP TABLE IF EXISTS temp.placeholder_candidates")
            db.commit()

    def _refresh_folder_context(self, db: sqlite3.Connection) -> None:
        directories = {
            row["relative_path"]: dict(row) for row in db.execute(
                "SELECT id,relative_path,name,status FROM directories"
            )
        }
        total = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        self._begin_phase("folder_evidence", total, "Ranking discovered folder names and surviving hierarchy")
        counts: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
        processed = 0
        cursor = db.execute("SELECT relative_path,size FROM files ORDER BY id")
        while True:
            rows = cursor.fetchmany(2000)
            if not rows:
                break
            for row in rows:
                parent = PurePosixPath(row["relative_path"]).parent
                while str(parent) not in ("", ".", "/"):
                    stat = counts[str(parent)]
                    stat[0] += 1
                    stat[1] += int(row["size"] or 0)
                    stat[2] += int(row["size"] or 0) == 0
                    parent = parent.parent
            processed += len(rows)
            self._progress(processed, total)
            self._check_cancel()
        now = utcnow()
        for relative, directory in directories.items():
            if relative == ".":
                continue
            file_count, byte_count, zero_count = counts.get(relative, [0, 0, 0])
            name = directory["name"] or PurePosixPath(relative).name
            lower_name = name.casefold().strip()
            depth = relative.count("/")
            score = 18.0 + math.log10(file_count + 1) * 18 - min(depth, 12) * 0.8
            if file_count == 0:
                score = 12.0 - min(depth, 12) * 0.3
            if lower_name in SYNTHETIC_FOLDER_NAMES or re.fullmatch(r"folder\s*\d+", lower_name):
                score -= 35
            if lower_name in SYSTEM_FOLDER_NAMES or directory["status"] == "ignored_system":
                score -= 45
            if re.search(r"\b(19|20)\d{2}\b", name):
                score += 8
            if " " in name and not re.fullmatch(r"folder\s*\d+", lower_name):
                score += 4
            db.execute(
                """INSERT INTO folder_context(
                     directory_id,name,relative_path,descendant_files,descendant_bytes,zero_files,
                     suggestion_score,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(directory_id) DO UPDATE SET
                     name=excluded.name,relative_path=excluded.relative_path,
                     descendant_files=excluded.descendant_files,descendant_bytes=excluded.descendant_bytes,
                     zero_files=excluded.zero_files,suggestion_score=excluded.suggestion_score,
                     updated_at=excluded.updated_at""",
                (directory["id"], name, relative, file_count, byte_count, zero_count, round(score, 2), now),
            )
        db.execute("DELETE FROM folder_context WHERE directory_id NOT IN (SELECT id FROM directories)")
        db.commit()

    @staticmethod
    def _clean_relative_path(value: str) -> str:
        return str(Path(*(sanitize_component(part) for part in PurePosixPath(value).parts if part not in ("", "."))))

    @staticmethod
    def _folder_lineage(relative_path: str, folder_reviews: dict[str, dict], include_self: bool = False) -> list[dict]:
        current = PurePosixPath(relative_path) if include_self else PurePosixPath(relative_path).parent
        lineage = []
        while str(current) not in ("", ".", "/"):
            reviewed = folder_reviews.get(str(current))
            if reviewed:
                lineage.append(reviewed)
            current = current.parent
        return lineage

    @staticmethod
    def _suffix_without_noise(relative_path: str, anchor_path: str, lineage: list[dict]) -> str:
        full_parts = list(PurePosixPath(relative_path).parts)
        anchor_parts = list(PurePosixPath(anchor_path).parts)
        removed_indexes = set()
        for item in lineage:
            if item["review_status"] != "noise":
                continue
            noise_parts = list(PurePosixPath(item["relative_path"]).parts)
            if full_parts[:len(noise_parts)] == noise_parts:
                removed_indexes.add(len(noise_parts) - 1)
        suffix = [
            part for index, part in enumerate(full_parts)
            if index >= len(anchor_parts) and index not in removed_indexes
        ]
        return str(Path(*suffix)) if suffix else ""

    def start_reconstruction_plan_refresh(self) -> bool:
        """Rebuild only the proposal layer after user/AI feedback changes."""
        with self.lock:
            if self.state["running"]:
                return False
            self.state.update(
                running=True, phase="reconstruction_plan", processed=0, total=0, rate=0.0,
                message="Applying folder reviews, context rules, and classifications", error=None,
            )
        self.stop_event.clear()
        threading.Thread(target=self._reconstruction_plan_wrapper, daemon=True).start()
        return True

    def _reconstruction_plan_wrapper(self) -> None:
        try:
            with connect(self.db_path) as db:
                self._build_reconstruction_proposals(db)
                db.commit()
            self.export_reconstruction_catalogs()
            result = self.reconstruction_summary()
            self._set_state(
                running=False, phase="complete",
                message=f"Feedback applied — {result['proposals']:,} proposals refreshed",
                error=None,
            )
        except ScanCancelled as exc:
            self._set_state(running=False, phase="stopped", message=str(exc), error=None)
        except Exception as exc:
            self._set_state(running=False, phase="failed", message="Plan refresh failed", error=str(exc))

    def _build_reconstruction_proposals(self, db: sqlite3.Connection) -> None:
        total = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        self._begin_phase("reconstruction_plan", total, "Applying feedback and building destination proposals")
        known_good: dict[int, tuple[str, str]] = {}
        for row in db.execute(
            """SELECT file_id,library,relative_path FROM known_good_matches
               ORDER BY file_id,LENGTH(relative_path),relative_path"""
        ):
            known_good.setdefault(row["file_id"], (row["library"], row["relative_path"]))
        folder_reviews = {row["relative_path"]: dict(row) for row in db.execute(
            """SELECT relative_path,COALESCE(NULLIF(user_label,''),name) label,review_status,notes
               FROM folder_context WHERE review_status!='unreviewed'
               ORDER BY LENGTH(relative_path) DESC"""
        )}
        context_rules = [dict(row) for row in db.execute(
            """SELECT context_type,label,details,match_text,destination FROM recovery_context
               WHERE COALESCE(TRIM(match_text),'')!='' AND COALESCE(TRIM(destination),'')!=''
               ORDER BY id"""
        )]
        facets: dict[int, dict[str, dict]] = defaultdict(dict)
        for item in db.execute(
            """SELECT file_id,facet_type,value,confidence,source FROM file_facets
               WHERE facet_type IN ('origin','sensitivity','topic','person','event','application')
               ORDER BY file_id,
                        CASE WHEN source='user' THEN 0 WHEN source LIKE 'ai:%' THEN 1 ELSE 2 END,
                        confidence DESC"""
        ):
            facets[item["file_id"]].setdefault(item["facet_type"], dict(item))
        processed = 0
        cursor = db.execute(
            """SELECT id,relative_path,name,size,media_kind,media_origin,sensitivity,
                      exif_date,video_creation_date,filename_date,known_good_match,
                      exact_group,similar_group,decision,validation
               FROM files ORDER BY id"""
        )
        while True:
            rows = cursor.fetchmany(1000)
            if not rows:
                break
            proposals = []
            for row in rows:
                file_id = row["id"]
                if file_id in known_good:
                    library, relative = known_good[file_id]
                    proposed = self._clean_relative_path(str(Path("Known Good") / sanitize_component(library) / relative))
                    basis, confidence, reason, status = (
                        "known_good_exact", 100, "byte-for-byte copy exists in a selected trusted library",
                        "covered_by_known_good",
                    )
                elif row["size"] == 0:
                    proposed = self._clean_relative_path(str(Path("Evidence Only") / row["relative_path"]))
                    basis, confidence, reason, status = (
                        "zero_byte_placeholder", 100, "retained as naming and path evidence; no content to export",
                        "evidence_only",
                    )
                else:
                    matching_folders = self._folder_lineage(row["relative_path"], folder_reviews)
                    system_context = next((item for item in matching_folders if item["review_status"] == "system"), None)
                    private_context = next((item for item in matching_folders if item["review_status"] == "private"), None)
                    structure_context = next(
                        (item for item in matching_folders if item["review_status"] in {"recognized", "private"}),
                        None,
                    )
                    noise_context = next((item for item in matching_folders if item["review_status"] == "noise"), None)
                    path_text = row["relative_path"].casefold()
                    context_rule = next(
                        (item for item in context_rules if item["match_text"].strip().casefold() in path_text),
                        None,
                    )
                    if system_context:
                        proposed = self._clean_relative_path(
                            str(Path("Excluded") / "System and Application Files" / row["relative_path"])
                        )
                        basis, confidence, reason, status = (
                            "system_folder", 100,
                            f"inside folder marked system/application: {system_context['label']}",
                            "excluded_system",
                        )
                    elif context_rule:
                        proposed = self._clean_relative_path(
                            str(Path(context_rule["destination"]) / row["name"])
                        )
                        basis, confidence, reason = (
                            "user_context_rule", 96,
                            f"matched user context rule: {context_rule['label']}",
                        )
                    elif structure_context:
                        suffix = self._suffix_without_noise(
                            row["relative_path"], structure_context["relative_path"], matching_folders,
                        ) or row["name"]
                        prefix = Path("Private") if private_context else Path()
                        proposed = self._clean_relative_path(
                            str(prefix / "Recovered Structure" / sanitize_component(structure_context["label"]) / suffix)
                        )
                        basis, confidence, reason = (
                            "private_folder" if private_context else "recognized_folder", 94,
                            "user-recognized private hierarchy" if private_context else "user-recognized surviving folder hierarchy",
                        )
                    else:
                        media = row["media_kind"] or "other"
                        file_facets = facets.get(file_id, {})
                        origin_facet = file_facets.get("origin", {})
                        sensitivity_facet = file_facets.get("sensitivity", {})
                        origin = origin_facet.get("value") or row["media_origin"]
                        sensitivity = sensitivity_facet.get("value") or row["sensitivity"]
                        base_names = {
                            "photo": "Photos", "video": "Videos", "audio": "Audio",
                            "document": "Documents", "email": "Email", "other": "Other Files",
                        }
                        pieces = []
                        if sensitivity in {"adult", "intimate", "possibly_sensitive"}:
                            pieces.append("Private")
                        pieces.extend([
                            "Organized Library",
                            "Media" if media in {"photo", "video", "audio"} else "Files",
                            base_names.get(media, "Other Files"),
                        ])
                        if origin and origin != "unknown":
                            pieces.append(sanitize_component(origin.replace("_", " ").title()))
                        classification_facet = None
                        for facet_type in ("event", "topic", "application"):
                            classification_facet = file_facets.get(facet_type, {})
                            value = classification_facet.get("value")
                            if value:
                                pieces.append(sanitize_component(value))
                                break
                        date_text = row["exif_date"] or row["video_creation_date"] or row["filename_date"]
                        if date_text:
                            pieces.extend(date_text[:7].split("-"))
                            confidence = 82 if (row["exif_date"] or row["video_creation_date"]) else 74
                            reason = "media type, origin, classification, and strongest available capture date"
                        else:
                            pieces.append("Unknown Date")
                            confidence = 45
                            reason = "media type, origin, and classification; no reliable capture date"
                        if noise_context:
                            reason += f"; ignored recovery-generated folder {noise_context['label']}"
                        pieces.append(row["name"])
                        proposed = self._clean_relative_path(str(Path(*pieces)))
                        interpretation_used = any(
                            item and item.get("source") != "deterministic"
                            for item in (origin_facet, sensitivity_facet, classification_facet)
                        )
                        if interpretation_used:
                            basis = "interpreted_category_noise_removed" if noise_context else "interpreted_category"
                        else:
                            basis = "sanitized_category_noise_removed" if noise_context else "sanitized_category"
                    if not system_context:
                        if row["decision"] == "reject":
                            status = "excluded"
                        elif row["validation"] in {"corrupt", "unreadable"}:
                            status = "needs_review"
                        elif row["decision"] == "undecided" and (row["exact_group"] or row["similar_group"]):
                            status = "duplicate_review"
                        else:
                            status = "proposed"
                proposals.append((file_id, proposed, confidence, basis, reason, status, utcnow()))
            db.executemany(
                """INSERT INTO reconstruction_proposals(
                     file_id,proposed_path,confidence,basis,reason,status,updated_at
                   ) VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(file_id) DO UPDATE SET
                     proposed_path=excluded.proposed_path,
                     confidence=excluded.confidence,
                     basis=excluded.basis,
                     reason=excluded.reason,
                     status=excluded.status,
                     review_state=CASE
                       WHEN reconstruction_proposals.proposed_path!=excluded.proposed_path
                            AND reconstruction_proposals.user_path IS NULL THEN 'pending'
                       ELSE reconstruction_proposals.review_state END,
                     reviewed_at=CASE
                       WHEN reconstruction_proposals.proposed_path!=excluded.proposed_path
                            AND reconstruction_proposals.user_path IS NULL THEN NULL
                       ELSE reconstruction_proposals.reviewed_at END,
                     updated_at=excluded.updated_at""",
                proposals,
            )
            db.commit()
            processed += len(rows)
            self._progress(processed, total)
            self._check_cancel()
        db.execute("DELETE FROM reconstruction_proposals WHERE file_id NOT IN (SELECT id FROM files)")
        self._build_reconstruction_directory_proposals(db, folder_reviews)

    def _build_reconstruction_directory_proposals(
        self, db: sqlite3.Connection, folder_reviews: dict[str, dict] | None = None,
    ) -> None:
        if folder_reviews is None:
            folder_reviews = {row["relative_path"]: dict(row) for row in db.execute(
                """SELECT relative_path,COALESCE(NULLIF(user_label,''),name) label,review_status,notes
                   FROM folder_context WHERE review_status!='unreviewed'"""
            )}
        db.execute("DELETE FROM reconstruction_directories")
        proposals = []
        now = utcnow()
        for row in db.execute("SELECT id,relative_path,name FROM directories WHERE relative_path!='.' ORDER BY id"):
            lineage = self._folder_lineage(row["relative_path"], folder_reviews, include_self=True)
            if not lineage:
                continue
            system_context = next((item for item in lineage if item["review_status"] == "system"), None)
            private_context = next((item for item in lineage if item["review_status"] == "private"), None)
            structure_context = next(
                (item for item in lineage if item["review_status"] in {"recognized", "private"}),
                None,
            )
            if system_context:
                proposed = self._clean_relative_path(
                    str(Path("Excluded") / "System and Application Files" / row["relative_path"])
                )
                proposals.append((
                    row["id"], proposed, 100, "system_folder",
                    f"inside folder marked system/application: {system_context['label']}",
                    "excluded_system", now,
                ))
                continue
            if not structure_context:
                continue
            suffix = self._suffix_without_noise(
                row["relative_path"], structure_context["relative_path"], lineage,
            )
            prefix = Path("Private") if private_context else Path()
            proposed = self._clean_relative_path(
                str(prefix / "Recovered Structure" / sanitize_component(structure_context["label"]) / suffix)
            )
            is_collapsed_noise = any(
                item["review_status"] == "noise" and item["relative_path"] == row["relative_path"]
                for item in lineage
            )
            proposals.append((
                row["id"], proposed, 96,
                "private_folder" if private_context else "recognized_folder",
                "empty and populated original directory structure beneath a user-recognized branch",
                "collapsed_noise" if is_collapsed_noise else "included", now,
            ))
        if proposals:
            db.executemany(
                """INSERT INTO reconstruction_directories(
                     directory_id,proposed_path,confidence,basis,reason,status,updated_at
                   ) VALUES(?,?,?,?,?,?,?)""",
                proposals,
            )

    def reconstruction_summary(self) -> dict:
        with connect(self.db_path) as db:
            media = [dict(row) for row in db.execute(
                "SELECT COALESCE(media_kind,'other') media_kind,COUNT(*) count,SUM(size) bytes FROM files GROUP BY media_kind ORDER BY count DESC"
            )]
            proposal_status = [dict(row) for row in db.execute(
                "SELECT status,COUNT(*) count FROM reconstruction_proposals GROUP BY status ORDER BY count DESC"
            )]
            row = db.execute(
                """SELECT
                     (SELECT COUNT(*) FROM reconstruction_proposals) proposals,
                     (SELECT COUNT(*) FROM folder_context) folder_suggestions,
                     (SELECT COUNT(*) FROM folder_context WHERE review_status!='unreviewed') reviewed_folders,
                     (SELECT COUNT(*) FROM file_relationships) relationships,
                     (SELECT COUNT(*) FROM known_good_matches) known_good_path_matches,
                     (SELECT COUNT(*) FROM files WHERE media_kind='video') videos,
                     (SELECT COUNT(*) FROM files WHERE media_kind='video' AND COALESCE(video_analysis_version,0)<?) pending_videos,
                     (SELECT COUNT(*) FROM recovery_context) context_items,
                     (SELECT COUNT(*) FROM reconstruction_directories WHERE status='included') directory_proposals,
                     (SELECT COUNT(*) FROM reconstruction_proposals
                       WHERE basis IN ('recognized_folder','private_folder','user_context_rule')) preserved_structure,
                     (SELECT COUNT(*) FROM reconstruction_proposals
                       WHERE basis LIKE 'interpreted_category%') interpreted_categories,
                     (SELECT COUNT(*) FROM reconstruction_proposals
                       WHERE basis LIKE 'sanitized_category%') sanitized_categories,
                     (SELECT COUNT(*) FROM reconstruction_proposals
                       WHERE status='proposed' AND confidence<70) low_evidence_proposals,
                     (SELECT COUNT(*) FROM reconstruction_proposals WHERE review_state='accepted') accepted_proposals,
                     (SELECT COUNT(*) FROM reconstruction_proposals WHERE review_state='pending') pending_proposals,
                     (SELECT COUNT(*) FROM reconstruction_proposals WHERE review_state='excluded') excluded_proposals,
                     (SELECT COUNT(*) FROM files WHERE media_kind IN ('photo','video') AND size>0 AND ai_updated_at IS NULL) ai_pending""",
                (VIDEO_ANALYSIS_VERSION,),
            ).fetchone()
        result = dict(row)
        result["media"] = media
        result["proposal_status"] = proposal_status
        return result

    def list_folder_context(self, query: str | None = None, limit: int = 250) -> list[dict]:
        clauses, params = [], []
        if query:
            clauses.append("(lower(name) LIKE ? OR lower(relative_path) LIKE ?)")
            pattern = f"%{query.casefold()}%"
            params.extend((pattern, pattern))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(max(1, min(int(limit), 1000)))
        with connect(self.db_path) as db:
            return [dict(row) for row in db.execute(
                f"""SELECT * FROM folder_context{where}
                    ORDER BY (review_status='unreviewed') DESC,suggestion_score DESC,descendant_files DESC
                    LIMIT ?""",
                params,
            )]

    def review_folder_context(
        self, directory_id: int, review_status: str, user_label: str = "", notes: str = "",
    ) -> None:
        if review_status not in {"unreviewed", "recognized", "noise", "system", "private"}:
            raise ValueError("invalid folder review status")
        label = sanitize_component(user_label)[:150] if user_label.strip() else None
        with connect(self.db_path) as db:
            db.execute(
                """UPDATE folder_context SET review_status=?,user_label=?,notes=?,updated_at=?
                   WHERE directory_id=?""",
                (review_status, label, notes.strip()[:1000] or None, utcnow(), directory_id),
            )
            db.commit()

    def add_recovery_context(
        self, context_type: str, label: str, details: str = "",
        match_text: str = "", destination: str = "",
    ) -> int:
        allowed = {"person", "device", "event", "application", "folder", "privacy", "general"}
        if context_type not in allowed:
            raise ValueError("invalid recovery context type")
        label = label.strip()[:150]
        if not label:
            raise ValueError("context label is required")
        match_text = match_text.strip()[:300]
        destination = self._clean_relative_path(destination.strip())[:500] if destination.strip() else ""
        if bool(match_text) != bool(destination):
            raise ValueError("A path match and destination are both required to create an automatic rule.")
        with connect(self.db_path) as db:
            cursor = db.execute(
                """INSERT INTO recovery_context(
                     context_type,label,details,match_text,destination,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?)""",
                (
                    context_type, label, details.strip()[:4000] or None,
                    match_text or None, destination or None, utcnow(), utcnow(),
                ),
            )
            db.commit()
            return int(cursor.lastrowid)

    def list_recovery_context(self) -> list[dict]:
        with connect(self.db_path) as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM recovery_context ORDER BY context_type,label"
            )]

    def delete_recovery_context(self, context_id: int) -> None:
        with connect(self.db_path) as db:
            cursor = db.execute("DELETE FROM recovery_context WHERE id=?", (context_id,))
            if cursor.rowcount == 0:
                raise FileNotFoundError("context clue not found")
            db.commit()

    def list_reconstruction_proposals(
        self, limit: int = 200, query: str | None = None, review_state: str | None = None,
        status: str | None = None, basis: str | None = None,
    ) -> list[dict]:
        clauses, params = [], []
        if query:
            clauses.append(
                "(lower(f.name) LIKE ? OR lower(f.relative_path) LIKE ? "
                "OR lower(COALESCE(p.user_path,p.proposed_path)) LIKE ?)"
            )
            pattern = f"%{query.casefold()}%"
            params.extend((pattern, pattern, pattern))
        if review_state:
            clauses.append("p.review_state=?")
            params.append(review_state)
        if status:
            clauses.append("p.status=?")
            params.append(status)
        if basis:
            clauses.append("p.basis=?")
            params.append(basis)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(max(1, min(int(limit), 1000)))
        with connect(self.db_path) as db:
            return [dict(row) for row in db.execute(
                f"""SELECT p.*,COALESCE(p.user_path,p.proposed_path) effective_path,
                            f.name,f.relative_path,f.media_kind,f.media_origin,f.sensitivity,
                            f.size,f.validation,f.decision,f.exact_group,f.similar_group
                   FROM reconstruction_proposals p JOIN files f ON f.id=p.file_id{where}
                   ORDER BY CASE p.status WHEN 'needs_review' THEN 0 WHEN 'duplicate_review' THEN 1 ELSE 2 END,
                            p.confidence ASC,f.id LIMIT ?""",
                params,
            )]

    def proposal_filter_options(self) -> dict:
        with connect(self.db_path) as db:
            return {
                "statuses": [row[0] for row in db.execute(
                    "SELECT DISTINCT status FROM reconstruction_proposals ORDER BY status"
                )],
                "bases": [row[0] for row in db.execute(
                    "SELECT DISTINCT basis FROM reconstruction_proposals ORDER BY basis"
                )],
            }

    def list_reconstruction_directories(self, limit: int = 250) -> list[dict]:
        with connect(self.db_path) as db:
            return [dict(row) for row in db.execute(
                """SELECT r.*,d.relative_path source_relative_path,d.name,
                          COALESCE(f.descendant_files,0) descendant_files
                   FROM reconstruction_directories r
                   JOIN directories d ON d.id=r.directory_id
                   LEFT JOIN folder_context f ON f.directory_id=r.directory_id
                   WHERE r.status='included'
                   ORDER BY (COALESCE(f.descendant_files,0)=0) DESC,r.proposed_path
                   LIMIT ?""",
                (max(1, min(int(limit), 1000)),),
            )]

    def review_reconstruction_proposal(
        self, file_id: int, review_state: str, user_path: str = "", note: str = "",
    ) -> None:
        if review_state not in {"pending", "accepted", "excluded"}:
            raise ValueError("invalid proposal review state")
        cleaned = self._clean_relative_path(user_path.strip())[:1000] if user_path.strip() else None
        if cleaned in {"", "."}:
            cleaned = None
        with connect(self.db_path) as db:
            row = db.execute(
                "SELECT proposed_path,status FROM reconstruction_proposals WHERE file_id=?", (file_id,)
            ).fetchone()
            if not row:
                raise FileNotFoundError("reconstruction proposal not found")
            if review_state == "accepted" and row["status"] != "proposed":
                raise ValueError("Resolve the file's exclusion, corruption, or duplicate decision before accepting it.")
            db.execute(
                """UPDATE reconstruction_proposals
                   SET review_state=?,user_path=?,review_note=?,reviewed_at=?,updated_at=? WHERE file_id=?""",
                (review_state, cleaned, note.strip()[:1000] or None, utcnow(), utcnow(), file_id),
            )
            db.commit()

    def bulk_accept_reconstruction(self, minimum_confidence: int = 85) -> int:
        threshold = max(0, min(int(minimum_confidence), 100))
        with connect(self.db_path) as db:
            cursor = db.execute(
                """UPDATE reconstruction_proposals SET review_state='accepted',reviewed_at=?,updated_at=?
                   WHERE review_state='pending' AND status='proposed' AND confidence>=?""",
                (utcnow(), utcnow(), threshold),
            )
            db.commit()
            return max(0, cursor.rowcount)

    def reconstruction_tree(self, limit: int = 100) -> list[dict]:
        branches: dict[str, dict] = {}
        with connect(self.db_path) as db:
            for row in db.execute(
                "SELECT proposed_path path FROM reconstruction_directories WHERE status='included'"
            ):
                parts = PurePosixPath(row["path"]).parts
                branch = "/".join(parts[:3]) if parts else "Other"
                item = branches.setdefault(
                    branch,
                    {"path": branch, "files": 0, "directories": 0, "bytes": 0,
                     "accepted": 0, "pending": 0, "excluded": 0, "minimum_confidence": 100},
                )
                item["directories"] += 1
            rows = db.execute(
                """SELECT COALESCE(p.user_path,p.proposed_path) path,p.review_state,p.status,p.confidence,f.size
                   FROM reconstruction_proposals p JOIN files f ON f.id=p.file_id"""
            )
            for row in rows:
                parts = PurePosixPath(row["path"]).parts
                branch = "/".join(parts[:3]) if parts else "Other"
                item = branches.setdefault(
                    branch,
                    {"path": branch, "files": 0, "directories": 0, "bytes": 0,
                     "accepted": 0, "pending": 0, "excluded": 0, "minimum_confidence": 100},
                )
                item["files"] += 1
                item["bytes"] += int(row["size"] or 0)
                state = row["review_state"] if row["review_state"] in {"accepted", "pending", "excluded"} else "pending"
                item[state] += 1
                item["minimum_confidence"] = min(item["minimum_confidence"], int(row["confidence"] or 0))
        return sorted(
            branches.values(), key=lambda item: (-(item["files"] + item["directories"]), item["path"])
        )[:limit]

    def _current_reconstruction_export_preview(self) -> dict:
        ready, blocked, unavailable, already_exported, collisions, total_bytes = 0, 0, 0, 0, 0, 0
        signature = []
        seen_destinations: set[str] = set()
        with connect(self.db_path) as db:
            directory_rows = db.execute(
                """SELECT directory_id,proposed_path,updated_at FROM reconstruction_directories
                   WHERE status='included' ORDER BY directory_id"""
            ).fetchall()
            rows = db.execute(
                """SELECT p.file_id,p.status,p.review_state,p.proposed_path,p.user_path,p.updated_at,
                          f.path,f.size,f.validation,f.exported_path
                   FROM reconstruction_proposals p JOIN files f ON f.id=p.file_id
                   WHERE p.review_state='accepted' ORDER BY p.file_id"""
            ).fetchall()
        for row in directory_rows:
            signature.append(("directory", row["directory_id"], row["proposed_path"], row["updated_at"]))
        for row in rows:
            effective = row["user_path"] or row["proposed_path"]
            signature.append(("file", row["file_id"], effective, row["updated_at"]))
            if row["exported_path"] and Path(row["exported_path"]).exists():
                already_exported += 1
                continue
            if row["status"] != "proposed" or row["validation"] in {"zero", "corrupt", "unreadable"}:
                blocked += 1
                continue
            if not Path(row["path"]).is_file():
                unavailable += 1
                continue
            destination_key = effective.casefold()
            destination = self.output / effective
            if destination_key in seen_destinations or destination.exists():
                collisions += 1
            seen_destinations.add(destination_key)
            ready += 1
            total_bytes += int(row["size"] or 0)
        token = blake3(json.dumps(signature, separators=(",", ":")).encode("utf-8")).hexdigest()
        return {
            "accepted": len(rows), "ready": ready, "blocked": blocked, "unavailable": unavailable,
            "already_exported": already_exported, "collisions": collisions, "bytes": total_bytes,
            "bytes_human": human_bytes(total_bytes), "directories": len(directory_rows), "token": token,
        }

    def reconstruction_export_preview(self, authorize: bool = False) -> dict:
        preview = self._current_reconstruction_export_preview()
        with connect(self.db_path) as db:
            if authorize:
                db.execute(
                    "INSERT OR REPLACE INTO settings(key,value) VALUES('reconstruction_export_token',?)",
                    (preview["token"],),
                )
                db.commit()
            stored = db.execute(
                "SELECT value FROM settings WHERE key='reconstruction_export_token'"
            ).fetchone()
        preview["authorized"] = bool(stored and stored["value"] == preview["token"])
        return preview

    def export_reconstruction(self, token: str) -> dict:
        if not self.allow_actions:
            raise PermissionError("Actions are disabled. Set ALLOW_ACTIONS=true before exporting.")
        preview = self.reconstruction_export_preview(authorize=False)
        if not preview["authorized"] or not token or token != preview["token"]:
            raise RuntimeError("The plan changed or has not been previewed. Generate a fresh dry run first.")
        exported, failed, skipped = 0, 0, 0
        with connect(self.db_path) as db:
            directory_rows = db.execute(
                """SELECT proposed_path FROM reconstruction_directories
                   WHERE status='included' ORDER BY LENGTH(proposed_path),proposed_path"""
            ).fetchall()
            for directory in directory_rows:
                destination = self.output / directory["proposed_path"]
                destination.mkdir(parents=True, exist_ok=True)
                self._normalize_output_directories(destination, self.output)
            rows = db.execute(
                """SELECT p.*,COALESCE(p.user_path,p.proposed_path) effective_path,f.*
                   FROM reconstruction_proposals p JOIN files f ON f.id=p.file_id
                   WHERE p.review_state='accepted' ORDER BY p.file_id"""
            ).fetchall()
            for row in rows:
                if row["status"] != "proposed" or row["validation"] in {"zero", "corrupt", "unreadable"}:
                    skipped += 1
                    continue
                if row["exported_path"] and Path(row["exported_path"]).exists():
                    skipped += 1
                    continue
                source = Path(row["path"])
                if not source.is_file():
                    skipped += 1
                    continue
                destination = self._safe_destination(self.output, row["effective_path"])
                try:
                    shutil.copy2(source, destination)
                    metadata_fixed = False
                    if row["is_image"] and not row["exif_date"] and row["filename_date"] and row["date_confidence"] >= 85:
                        metadata_fixed = apply_date_metadata(destination, row["filename_date"])
                    self._normalize_output_file(destination)
                    db.execute("UPDATE files SET exported_path=? WHERE id=?", (str(destination), row["file_id"]))
                    db.execute(
                        """INSERT INTO actions(
                             created_at,action,file_id,source_path,destination_path,status,detail
                           ) VALUES(?,?,?,?,?,'complete',?)""",
                        (
                            utcnow(), "reconstruction_export", row["file_id"], str(source), str(destination),
                            "filename date applied" if metadata_fixed else "accepted reconstruction proposal",
                        ),
                    )
                    exported += 1
                except Exception as exc:
                    failed += 1
                    db.execute(
                        """INSERT INTO actions(
                             created_at,action,file_id,source_path,destination_path,status,detail
                           ) VALUES(?,?,?,?,?,'failed',?)""",
                        (utcnow(), "reconstruction_export", row["file_id"], str(source), str(destination), str(exc)[:500]),
                    )
                if (exported + failed) % 50 == 0:
                    db.commit()
            db.execute("DELETE FROM settings WHERE key='reconstruction_export_token'")
            db.commit()
        self.export_catalog(self.output)
        self.export_reconstruction_catalogs(self.output)
        return {"exported": exported, "failed": failed, "skipped": skipped}

    def set_file_facet(self, file_id: int, facet_type: str, value: str, reason: str = "") -> None:
        allowed = {"origin", "sensitivity", "topic", "person", "event", "application", "media_type"}
        if facet_type not in allowed:
            raise ValueError("invalid facet type")
        value = value.strip()[:150]
        if not value:
            raise ValueError("facet value is required")
        with connect(self.db_path) as db:
            db.execute(
                """INSERT OR REPLACE INTO file_facets(
                     file_id,facet_type,value,confidence,source,reason,updated_at
                   ) VALUES(?,?,?,100,'user',?,?)""",
                (file_id, facet_type, value, reason.strip()[:500] or "user classification", utcnow()),
            )
            if facet_type == "origin":
                db.execute("UPDATE files SET media_origin=? WHERE id=?", (value, file_id))
            elif facet_type == "sensitivity":
                db.execute("UPDATE files SET sensitivity=? WHERE id=?", (value, file_id))
            db.commit()

    def file_facets(self, file_id: int) -> list[dict]:
        with connect(self.db_path) as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM file_facets WHERE file_id=? ORDER BY facet_type,confidence DESC", (file_id,)
            )]

    def ai_provider_settings(self) -> dict:
        from .ai import endpoint_is_local

        with connect(self.db_path) as db:
            row = db.execute("SELECT * FROM ai_provider_settings WHERE id=1").fetchone()
        result = dict(row) if row else {
            "id": 1, "provider_id": "custom", "provider_name": "Local AI", "endpoint": "", "model": "",
            "api_key_env": "",
            "enabled": 0, "allow_cloud_media": 0, "allow_sensitive_media": 0, "updated_at": None,
        }
        result["is_local"] = endpoint_is_local(result.get("endpoint") or "") if result.get("endpoint") else None
        result["has_api_key"] = bool(self._load_ai_secret())
        return result

    def _ai_secret_path(self) -> Path:
        return self.db_path.parent / "ai-provider-secret.json"

    def _load_ai_secret(self) -> str:
        try:
            value = json.loads(self._ai_secret_path().read_text(encoding="utf-8"))
            return str(value.get("api_key") or "").strip()
        except (FileNotFoundError, OSError, TypeError, ValueError, json.JSONDecodeError):
            return ""

    def _save_ai_secret(self, api_key: str) -> None:
        target = self._ai_secret_path()
        if not api_key:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        try:
            temporary.write_text(json.dumps({"api_key": api_key}), encoding="utf-8")
            temporary.chmod(0o600)
            temporary.replace(target)
            target.chmod(0o600)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _ai_provider_config_values(self, overrides: dict | None = None) -> dict:
        values = self.ai_provider_settings()
        if overrides:
            values.update(overrides)
        supplied_key = str(values.get("api_key") or "").strip()
        values["api_key"] = supplied_key or self._load_ai_secret()
        return values

    def save_ai_provider_settings(self, values: dict) -> dict:
        from .ai import ProviderConfig

        config = ProviderConfig.from_mapping(values)
        config.validate()
        new_key = str(values.get("api_key") or "").strip()
        clear_key = bool(values.get("clear_api_key"))
        if new_key:
            self._save_ai_secret(new_key)
        elif clear_key:
            self._save_ai_secret("")
        with connect(self.db_path) as db:
            db.execute(
                """INSERT INTO ai_provider_settings(
                     id,provider_id,provider_name,endpoint,model,api_key_env,enabled,
                     allow_cloud_media,allow_sensitive_media,updated_at
                   ) VALUES(1,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     provider_id=excluded.provider_id,provider_name=excluded.provider_name,
                     endpoint=excluded.endpoint,model=excluded.model,
                     api_key_env=excluded.api_key_env,enabled=excluded.enabled,
                     allow_cloud_media=excluded.allow_cloud_media,
                     allow_sensitive_media=excluded.allow_sensitive_media,updated_at=excluded.updated_at""",
                (
                    config.provider_id[:50], config.provider_name[:100], config.endpoint[:500] or None,
                    config.model[:200] or None,
                    config.api_key_env[:100] or None, int(config.enabled), int(config.allow_cloud_media),
                    int(config.allow_sensitive_media), utcnow(),
                ),
            )
            db.commit()
        return self.ai_provider_settings()

    def test_ai_provider(self, values: dict | None = None) -> dict:
        from .ai import AIProviderClient, ProviderConfig

        config_values = self._ai_provider_config_values(values)
        config_values["enabled"] = False
        config = ProviderConfig.from_mapping(config_values)
        return AIProviderClient(config).test_connection()

    def start_structure_ai(self, limit: int = 300) -> int:
        settings = self._ai_provider_config_values()
        if not settings.get("enabled"):
            raise RuntimeError("Save and enable an AI provider before interpreting folder context.")
        requested = max(25, min(int(limit), 1000))
        with connect(self.db_path) as db:
            available = db.execute("SELECT COUNT(*) FROM folder_context").fetchone()[0]
        if not available:
            raise RuntimeError("Build the reconstruction plan before interpreting folder context.")
        with self.lock:
            if self.state["running"]:
                raise RuntimeError("Another scan or analysis job is already running.")
            self.state.update(
                running=True, phase="ai_structure", processed=0, total=1, rate=0.0,
                message="AI is interpreting folder reviews, empty directories, and context", error=None,
            )
        self.stop_event.clear()
        threading.Thread(target=self._structure_ai_wrapper, args=(requested,), daemon=True).start()
        return min(requested, available)

    def _structure_ai_wrapper(self, limit: int) -> None:
        from .ai import AIProviderClient, ProviderConfig

        settings = self._ai_provider_config_values()
        config = ProviderConfig.from_mapping(settings)
        source = f"ai:{config.provider_name}"[:100]
        with connect(self.db_path) as db:
            folders = [dict(row) for row in db.execute(
                """SELECT directory_id,relative_path,name,descendant_files,descendant_bytes,zero_files,
                          review_status,user_label,notes,suggestion_score
                   FROM folder_context
                   ORDER BY (review_status!='unreviewed') DESC,(notes IS NOT NULL) DESC,
                            (descendant_files=0) DESC,suggestion_score DESC,directory_id
                   LIMIT ?""",
                (limit,),
            )]
            run_id = int(db.execute(
                """INSERT INTO ai_runs(
                     file_id,provider_name,model,status,request_kind,created_at
                   ) VALUES(NULL,?,?, 'running','structure_analysis',?)""",
                (config.provider_name, config.model, utcnow()),
            ).lastrowid)
            db.commit()
        try:
            self._check_cancel()
            result = AIProviderClient(config).analyze_structure(folders, self.list_recovery_context())
            self._check_cancel()
            valid_paths = {item["relative_path"]: item for item in folders}
            folder_items = result.get("folder_suggestions")
            rule_items = result.get("path_rules")
            if not isinstance(folder_items, list):
                folder_items = []
            if not isinstance(rule_items, list):
                rule_items = []
            saved = []
            now = utcnow()
            def confidence_of(item: dict) -> int:
                try:
                    return max(0, min(int(item.get("confidence") or 0), 100))
                except (TypeError, ValueError):
                    return 0
            for item in folder_items[:500]:
                if not isinstance(item, dict):
                    continue
                relative = str(item.get("relative_path") or "").strip()
                status = str(item.get("review_status") or "").strip()
                target = valid_paths.get(relative)
                if not target or status not in {"recognized", "private", "noise", "system"}:
                    continue
                label_text = str(item.get("user_label") or "").strip()
                saved.append((
                    "folder", target["directory_id"], relative, status,
                    sanitize_component(label_text)[:150] if label_text else None,
                    None, None, confidence_of(item),
                    str(item.get("reason") or "")[:1000] or None, source, "pending", now, now,
                ))
            for item in rule_items[:200]:
                if not isinstance(item, dict):
                    continue
                match_text = str(item.get("match_text") or "").strip()[:300]
                destination = self._clean_relative_path(str(item.get("destination") or "").strip())[:500]
                if not match_text or not destination or destination == ".":
                    continue
                saved.append((
                    "rule", None, None, None, str(item.get("label") or "AI path rule")[:150],
                    match_text, destination, confidence_of(item),
                    str(item.get("reason") or "")[:1000] or None, source, "pending", now, now,
                ))
            with connect(self.db_path) as db:
                db.execute("DELETE FROM ai_structure_suggestions WHERE status='pending'")
                if saved:
                    db.executemany(
                        """INSERT INTO ai_structure_suggestions(
                             suggestion_type,directory_id,relative_path,review_status,user_label,
                             match_text,destination,confidence,reason,source,status,created_at,updated_at
                           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        saved,
                    )
                db.execute(
                    """UPDATE ai_runs SET status='complete',response_json=?,completed_at=? WHERE id=?""",
                    (json.dumps(result, ensure_ascii=False), utcnow(), run_id),
                )
                db.commit()
            self._set_state(
                running=False, phase="complete", processed=1, total=1,
                message=f"AI folder interpretation ready — {len(saved):,} suggestions to review", error=None,
            )
        except ScanCancelled as exc:
            with connect(self.db_path) as db:
                db.execute(
                    "UPDATE ai_runs SET status='cancelled',error=?,completed_at=? WHERE id=?",
                    (str(exc), utcnow(), run_id),
                )
                db.commit()
            self._set_state(running=False, phase="stopped", message=str(exc), error=None)
        except Exception as exc:
            with connect(self.db_path) as db:
                db.execute(
                    "UPDATE ai_runs SET status='failed',error=?,completed_at=? WHERE id=?",
                    (str(exc)[:1000], utcnow(), run_id),
                )
                db.commit()
            self._set_state(running=False, phase="failed", message="AI folder interpretation failed", error=str(exc))

    def list_structure_suggestions(self, status: str = "pending", limit: int = 250) -> list[dict]:
        with connect(self.db_path) as db:
            return [dict(row) for row in db.execute(
                """SELECT * FROM ai_structure_suggestions WHERE status=?
                   ORDER BY confidence DESC,id LIMIT ?""",
                (status, max(1, min(int(limit), 1000))),
            )]

    def review_structure_suggestion(self, suggestion_id: int, decision: str) -> bool:
        if decision not in {"accepted", "rejected"}:
            raise ValueError("invalid suggestion decision")
        with connect(self.db_path) as db:
            item = db.execute(
                "SELECT * FROM ai_structure_suggestions WHERE id=? AND status='pending'", (suggestion_id,)
            ).fetchone()
            if not item:
                raise FileNotFoundError("pending AI structure suggestion not found")
            if decision == "accepted":
                if item["suggestion_type"] == "folder":
                    db.execute(
                        """UPDATE folder_context SET review_status=?,user_label=COALESCE(?,user_label),
                                  notes=CASE WHEN notes IS NULL THEN ? ELSE notes END,updated_at=?
                           WHERE directory_id=?""",
                        (
                            item["review_status"], item["user_label"], item["reason"],
                            utcnow(), item["directory_id"],
                        ),
                    )
                elif item["suggestion_type"] == "rule":
                    db.execute(
                        """INSERT INTO recovery_context(
                             context_type,label,details,match_text,destination,created_at,updated_at
                           ) VALUES('folder',?,?,?,?,?,?)""",
                        (
                            item["user_label"] or "AI path rule", item["reason"], item["match_text"],
                            item["destination"], utcnow(), utcnow(),
                        ),
                    )
            db.execute(
                "UPDATE ai_structure_suggestions SET status=?,updated_at=? WHERE id=?",
                (decision, utcnow(), suggestion_id),
            )
            db.commit()
        return decision == "accepted"

    def analyze_file_with_ai(self, file_id: int) -> dict:
        from .ai import AIProviderClient, ProviderConfig

        row = self.get_file(file_id)
        if not row:
            raise FileNotFoundError("catalog row not found")
        preview = self.ensure_media_preview(file_id)
        settings = self._ai_provider_config_values()
        config = ProviderConfig.from_mapping(settings)
        metadata = {
            "name": row["name"], "relative_path": row["relative_path"], "extension": row["extension"],
            "size": row["size"], "media_kind": row["media_kind"], "media_origin": row["media_origin"],
            "sensitivity": row["sensitivity"], "width": row["width"], "height": row["height"],
            "duration": row["video_duration"], "video_codec": row["video_codec"],
            "audio_codec": row["audio_codec"], "exif_date": row["exif_date"],
            "video_creation_date": row["video_creation_date"], "filename_date": row["filename_date"],
            "existing_facets": self.file_facets(file_id),
        }
        with connect(self.db_path) as db:
            run = db.execute(
                """INSERT INTO ai_runs(
                     file_id,provider_name,model,status,request_kind,created_at
                   ) VALUES(?,?,?,'running','media_analysis',?)""",
                (file_id, config.provider_name, config.model, utcnow()),
            )
            run_id = int(run.lastrowid)
            db.commit()
        try:
            result = AIProviderClient(config).analyze_media(preview, metadata, self.list_recovery_context())
        except Exception as exc:
            with connect(self.db_path) as db:
                db.execute(
                    "UPDATE ai_runs SET status='failed',error=?,completed_at=? WHERE id=?",
                    (str(exc)[:1000], utcnow(), run_id),
                )
                db.commit()
            raise
        confidence = max(0, min(int(result.get("confidence") or 0), 100))
        topics = result.get("topics") if isinstance(result.get("topics"), list) else []
        people = result.get("people_labels") if isinstance(result.get("people_labels"), list) else []
        source = f"ai:{config.provider_name}"[:100]
        facets = []
        for facet_type, raw_value in (("origin", result.get("origin")), ("sensitivity", result.get("sensitivity"))):
            if raw_value:
                facets.append((file_id, facet_type, str(raw_value)[:150], confidence, source, str(result.get("reason") or "")[:500], utcnow()))
        for topic in topics[:50]:
            facets.append((file_id, "topic", str(topic)[:150], confidence, source, "AI media analysis", utcnow()))
        for person in people[:50]:
            facets.append((file_id, "person", str(person)[:150], confidence, source, "AI media analysis; identity not independently verified", utcnow()))
        with connect(self.db_path) as db:
            db.execute("DELETE FROM file_facets WHERE file_id=? AND source=?", (file_id, source))
            if facets:
                db.executemany(
                    """INSERT OR REPLACE INTO file_facets(
                         file_id,facet_type,value,confidence,source,reason,updated_at
                       ) VALUES(?,?,?,?,?,?,?)""",
                    facets,
                )
            db.execute(
                """UPDATE files SET ai_caption=?,ai_people=?,ai_objects=?,ai_tags=?,ai_model=?,ai_updated_at=?
                   WHERE id=?""",
                (
                    str(result.get("caption") or "")[:4000] or None,
                    json.dumps(people, ensure_ascii=False), json.dumps(topics, ensure_ascii=False),
                    json.dumps(result, ensure_ascii=False), config.model, utcnow(), file_id,
                ),
            )
            origin = str(result.get("origin") or "").strip()[:150]
            sensitivity = str(result.get("sensitivity") or "").strip()[:150]
            if origin and origin != "unknown" and confidence >= 60:
                db.execute(
                    "UPDATE files SET media_origin=? WHERE id=? AND media_origin='unknown'",
                    (origin, file_id),
                )
            if sensitivity and sensitivity != "unknown" and confidence >= 60:
                db.execute(
                    "UPDATE files SET sensitivity=? WHERE id=? AND sensitivity='unknown'",
                    (sensitivity, file_id),
                )
            db.execute(
                """UPDATE ai_runs SET status='complete',response_json=?,completed_at=? WHERE id=?""",
                (json.dumps(result, ensure_ascii=False), utcnow(), run_id),
            )
            questions = result.get("questions") if isinstance(result.get("questions"), list) else []
            for question in questions[:20]:
                text = str(question).strip()[:1000]
                if text:
                    db.execute(
                        """INSERT INTO review_questions(
                             file_id,source,question,status,created_at,updated_at
                           ) VALUES(?,? ,?,'open',?,?)""",
                        (file_id, source, text, utcnow(), utcnow()),
                    )
            exact_group = db.execute("SELECT exact_group FROM files WHERE id=?", (file_id,)).fetchone()[0]
            if exact_group:
                duplicate_ids = [row[0] for row in db.execute(
                    "SELECT id FROM files WHERE exact_group=? AND id!=?", (exact_group, file_id)
                )]
                for duplicate_id in duplicate_ids:
                    db.execute("DELETE FROM file_facets WHERE file_id=? AND source=?", (duplicate_id, source))
                    if facets:
                        db.executemany(
                            """INSERT OR REPLACE INTO file_facets(
                                 file_id,facet_type,value,confidence,source,reason,updated_at
                               ) VALUES(?,?,?,?,?,?,?)""",
                            [
                                (duplicate_id, facet_type, value, facet_confidence, facet_source, reason, updated_at)
                                for _, facet_type, value, facet_confidence, facet_source, reason, updated_at in facets
                            ],
                        )
                    db.execute(
                        """UPDATE files SET ai_caption=?,ai_people=?,ai_objects=?,ai_tags=?,ai_model=?,ai_updated_at=?,
                                  media_origin=CASE WHEN media_origin='unknown' AND ?!='unknown' THEN ? ELSE media_origin END,
                                  sensitivity=CASE WHEN sensitivity='unknown' AND ?!='unknown' THEN ? ELSE sensitivity END
                           WHERE id=?""",
                        (
                            str(result.get("caption") or "")[:4000] or None,
                            json.dumps(people, ensure_ascii=False), json.dumps(topics, ensure_ascii=False),
                            json.dumps(result, ensure_ascii=False), config.model, utcnow(),
                            origin or "unknown", origin or "unknown",
                            sensitivity or "unknown", sensitivity or "unknown", duplicate_id,
                        ),
                    )
            db.commit()
        return result

    def _ai_batch_candidates(
        self, media_kind: str = "all", pending_only: bool = True, uncertain_only: bool = True,
        limit: int = 100,
    ) -> list[int]:
        if media_kind not in {"all", "photo", "video"}:
            raise ValueError("invalid media type")
        clauses = ["media_kind IN ('photo','video')", "size>0", "validation NOT IN ('zero','corrupt','unreadable')"]
        params: list[object] = []
        if media_kind != "all":
            clauses.append("media_kind=?")
            params.append(media_kind)
        if pending_only:
            clauses.append("ai_updated_at IS NULL")
        if uncertain_only:
            clauses.append("(media_origin='unknown' OR category_confidence<80 OR sensitivity='unknown')")
        settings = self.ai_provider_settings()
        if not settings.get("allow_sensitive_media"):
            clauses.append("sensitivity NOT IN ('adult','intimate','possibly_sensitive')")
        requested = max(1, min(int(limit), 5000))
        candidates = []
        seen_groups: set[str] = set()
        with connect(self.db_path) as db:
            rows = db.execute(
                f"SELECT id,exact_group FROM files WHERE {' AND '.join(clauses)} ORDER BY id", params
            )
            for row in rows:
                key = f"exact:{row['exact_group']}" if row["exact_group"] else f"file:{row['id']}"
                if key in seen_groups:
                    continue
                seen_groups.add(key)
                candidates.append(int(row["id"]))
                if len(candidates) >= requested:
                    break
        return candidates

    def ai_batch_candidate_count(
        self, media_kind: str = "all", pending_only: bool = True, uncertain_only: bool = True,
    ) -> int:
        if media_kind not in {"all", "photo", "video"}:
            raise ValueError("invalid media type")
        clauses = ["media_kind IN ('photo','video')", "size>0", "validation NOT IN ('zero','corrupt','unreadable')"]
        params: list[object] = []
        if media_kind != "all":
            clauses.append("media_kind=?")
            params.append(media_kind)
        if pending_only:
            clauses.append("ai_updated_at IS NULL")
        if uncertain_only:
            clauses.append("(media_origin='unknown' OR category_confidence<80 OR sensitivity='unknown')")
        if not self.ai_provider_settings().get("allow_sensitive_media"):
            clauses.append("sensitivity NOT IN ('adult','intimate','possibly_sensitive')")
        with connect(self.db_path) as db:
            return int(db.execute(
                f"""SELECT COUNT(DISTINCT CASE WHEN exact_group IS NOT NULL
                          THEN 'exact:'||exact_group ELSE 'file:'||id END)
                    FROM files WHERE {' AND '.join(clauses)}""",
                params,
            ).fetchone()[0])

    def start_ai_batch(
        self, media_kind: str = "all", pending_only: bool = True,
        uncertain_only: bool = True, limit: int = 100,
    ) -> int:
        settings = self.ai_provider_settings()
        if not settings.get("enabled"):
            raise RuntimeError("Save and enable an AI provider before starting a batch.")
        candidates = self._ai_batch_candidates(media_kind, pending_only, uncertain_only, limit)
        if not candidates:
            raise RuntimeError("No media matches the selected AI batch filters.")
        with self.lock:
            if self.state["running"]:
                raise RuntimeError("Another scan or analysis job is already running.")
            self.state.update(
                running=True, phase="ai_batch", processed=0, total=len(candidates), rate=0.0,
                message=f"Starting AI analysis for {len(candidates):,} representative files", error=None,
            )
        self.stop_event.clear()
        threading.Thread(target=self._ai_batch_wrapper, args=(candidates,), daemon=True).start()
        return len(candidates)

    def _ai_batch_wrapper(self, candidates: list[int]) -> None:
        completed = failed = 0
        self.phase_started = time.monotonic()
        try:
            for file_id in candidates:
                self._check_cancel()
                try:
                    self.analyze_file_with_ai(file_id)
                    completed += 1
                except Exception:
                    failed += 1
                processed = completed + failed
                self._progress(
                    processed, len(candidates),
                    f"AI media analysis — {completed:,} complete, {failed:,} failed",
                )
            with connect(self.db_path) as db:
                if db.execute("SELECT COUNT(*) FROM reconstruction_proposals").fetchone()[0]:
                    self._build_reconstruction_proposals(db)
                    db.commit()
            self.export_reconstruction_catalogs()
            self._set_state(
                running=False, phase="complete", processed=len(candidates), total=len(candidates),
                message=f"AI batch complete — {completed:,} analyzed, {failed:,} failed", error=None,
            )
        except ScanCancelled as exc:
            self._set_state(
                running=False, phase="stopped",
                message=f"{exc} AI results already completed were kept.", error=None,
            )
        except Exception as exc:
            self._set_state(running=False, phase="failed", message="AI batch failed", error=str(exc))

    def recent_ai_runs(self, limit: int = 25) -> list[dict]:
        with connect(self.db_path) as db:
            return [dict(row) for row in db.execute(
                """SELECT r.*,f.name FROM ai_runs r LEFT JOIN files f ON f.id=r.file_id
                   ORDER BY r.id DESC LIMIT ?""",
                (max(1, min(int(limit), 100)),),
            )]

    def list_review_questions(self, status: str = "open", limit: int = 100) -> list[dict]:
        with connect(self.db_path) as db:
            return [dict(row) for row in db.execute(
                """SELECT q.*,f.name,f.relative_path,f.media_kind,f.sensitivity
                   FROM review_questions q LEFT JOIN files f ON f.id=q.file_id
                   WHERE q.status=? ORDER BY q.id LIMIT ?""",
                (status, max(1, min(int(limit), 500))),
            )]

    def answer_review_question(self, question_id: int, answer: str, dismiss: bool = False) -> None:
        answer = answer.strip()[:4000]
        if not dismiss and not answer:
            raise ValueError("Enter an answer or dismiss the question.")
        with connect(self.db_path) as db:
            question = db.execute("SELECT * FROM review_questions WHERE id=?", (question_id,)).fetchone()
            if not question:
                raise FileNotFoundError("review question not found")
            status = "dismissed" if dismiss else "answered"
            db.execute(
                "UPDATE review_questions SET status=?,answer=?,updated_at=? WHERE id=?",
                (status, answer or None, utcnow(), question_id),
            )
            if not dismiss:
                db.execute(
                    """INSERT INTO recovery_context(context_type,label,details,created_at,updated_at)
                       VALUES('general',?,?,?,?)""",
                    (f"Answer: {question['question'][:120]}", answer, utcnow(), utcnow()),
                )
            db.commit()

    def _build_similar_groups(self, radius: int = 6) -> None:
        with connect(self.db_path) as db:
            total = db.execute("SELECT COUNT(*) FROM files WHERE phash IS NOT NULL AND validation='valid'").fetchone()[0]
            self._begin_phase("similarity", total, "Indexing visually similar images without all-pairs comparisons")
            tree = BKTree()
            # One representative per pHash/aspect bucket prevents huge groups of blank or
            # near-identical thumbnails from degenerating into repeated all-member comparisons.
            hash_representatives: dict[int, dict[int, int]] = defaultdict(dict)
            dimensions: dict[int, tuple[int, int]] = {}
            union = UnionFind()
            member_ids: list[int] = []
            cursor = db.execute("SELECT id,phash,width,height FROM files WHERE phash IS NOT NULL AND validation='valid' ORDER BY id")
            processed = 0
            while batch := cursor.fetchmany(self.batch_size * 4):
                self._check_cancel()
                for row in batch:
                    value = int(row["phash"], 16)
                    member_ids.append(row["id"])
                    dimensions[row["id"]] = (row["width"] or 1, row["height"] or 1)
                    current_ratio = dimensions[row["id"]][0] / max(dimensions[row["id"]][1], 1)
                    ratio_bucket = round(math.log(max(current_ratio, 0.001)) / 0.06)
                    for neighbor in tree.search(value, radius):
                        candidates = hash_representatives[neighbor]
                        for bucket in range(ratio_bucket - 2, ratio_bucket + 3):
                            other_id = candidates.get(bucket)
                            if other_id is None:
                                continue
                            left = dimensions[row["id"]]
                            right = dimensions[other_id]
                            left_ratio = left[0] / max(left[1], 1)
                            right_ratio = right[0] / max(right[1], 1)
                            if abs(math.log(max(left_ratio, 0.001) / max(right_ratio, 0.001))) <= 0.12:
                                union.union(row["id"], other_id)
                    tree.add(value)
                    hash_representatives[value].setdefault(ratio_bucket, row["id"])
                processed += len(batch)
                self._progress(processed, total)
            groups: dict[int, list[int]] = defaultdict(list)
            for file_id in member_ids:
                groups[union.find(file_id)].append(file_id)
            db.execute("UPDATE files SET similar_group=NULL")
            group_number = 1
            for members in groups.values():
                if len(members) < 2:
                    continue
                db.executemany("UPDATE files SET similar_group=? WHERE id=?", ((group_number, item) for item in members))
                group_number += 1
            db.commit()

    def summary(self) -> dict:
        with connect(self.db_path) as db:
            row = db.execute(
                """SELECT COUNT(*) files,COALESCE(SUM(size),0) bytes,
                   SUM(validation='zero') zero_files,SUM(validation='corrupt') corrupt_files,
                   SUM(is_image=1) images,SUM(media_kind='video') videos,SUM(exact_group IS NOT NULL) exact_members,
                   COUNT(DISTINCT exact_group) exact_groups,COUNT(DISTINCT similar_group) similar_groups,
                   SUM(filename_date IS NOT NULL AND exif_date IS NULL) date_proposals,
                   SUM(known_good_match=1) known_good_matches
                   FROM files"""
            ).fetchone()
            categories = [dict(item) for item in db.execute("SELECT category,COUNT(*) count FROM files GROUP BY category ORDER BY count DESC")]
            reference_files = db.execute("SELECT COUNT(*) FROM reference_files").fetchone()[0]
            directory_row = db.execute(
                """SELECT COUNT(*) directories,
                          SUM(status='unreadable') unreadable_directories,
                          SUM(status='ignored_system') ignored_directories
                   FROM directories"""
            ).fetchone()
            reference_libraries = [dict(item) for item in db.execute(
                "SELECT library,COUNT(*) files,SUM(content_hash IS NOT NULL) hashed FROM reference_files GROUP BY library ORDER BY library"
            )]
        result = dict(row)
        result["categories"] = categories
        result["reference_files"] = reference_files
        result.update(dict(directory_row))
        result["reference_libraries"] = reference_libraries
        result["reference_selections"] = self.selected_references()
        result["reference_root_available"] = bool(self.reference_root and self.reference_root.is_dir())
        result["source"] = self.source_diagnostic()
        result["last_source_inventory"] = None
        with connect(self.db_path) as db:
            inventory_row = db.execute("SELECT value FROM settings WHERE key='last_source_inventory'").fetchone()
        if inventory_row:
            try:
                result["last_source_inventory"] = json.loads(inventory_row["value"])
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
        result["bytes_human"] = human_bytes(result["bytes"])
        result["allow_actions"] = self.allow_actions
        return result

    def group_rows(self, kind: str, limit: int = 100) -> list[dict]:
        column = "exact_group" if kind == "exact" else "similar_group"
        with connect(self.db_path) as db:
            group_ids = [row[0] for row in db.execute(
                f"SELECT {column} FROM files WHERE {column} IS NOT NULL GROUP BY {column} ORDER BY SUM(size) DESC LIMIT ?", (limit,)
            )]
            groups = []
            for group_id in group_ids:
                items = [dict(row) for row in db.execute(
                    f"SELECT * FROM files WHERE {column}=? ORDER BY quality_score DESC,size DESC,path", (group_id,)
                )]
                groups.append({"id": group_id, "items": items, "recommended_id": items[0]["id"] if items else None})
            return groups

    def list_files(
        self, category: str | None = None, validation: str | None = None,
        known_good: bool | None = None, media_kind: str | None = None, limit: int = 500,
    ) -> list[dict]:
        clauses, params = [], []
        if category:
            clauses.append("category=?")
            params.append(category)
        if validation:
            clauses.append("validation=?")
            params.append(validation)
        if known_good is not None:
            clauses.append("known_good_match=?")
            params.append(1 if known_good else 0)
        if media_kind:
            clauses.append("media_kind=?")
            params.append(media_kind)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(limit)
        with connect(self.db_path) as db:
            return [dict(row) for row in db.execute(f"SELECT * FROM files{where} ORDER BY quality_score DESC,id LIMIT ?", params)]

    def get_file(self, file_id: int) -> sqlite3.Row | None:
        with connect(self.db_path) as db:
            return db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()

    def ensure_media_preview(self, file_id: int) -> Path:
        row = self.get_file(file_id)
        if not row:
            raise FileNotFoundError("catalog row not found")
        source = Path(row["path"])
        if not source.exists() or not source.is_file():
            raise FileNotFoundError("source media is unavailable")
        if row["media_kind"] not in {"photo", "video"} and not row["is_image"]:
            raise ValueError("preview is available only for photos and videos")
        cache = self.db_path.parent / "media_cache"
        cache.mkdir(parents=True, exist_ok=True)
        cache.chmod(0o775)
        if os.geteuid() == 0:
            os.chown(cache, self.output_uid, self.output_gid)
        destination = cache / f"{file_id}-{row['mtime_ns']}-{row['size']}.jpg"
        if destination.exists():
            return destination
        if row["media_kind"] == "video":
            duration = float(row["video_duration"] or 0)
            positions = [0.0] if duration <= 1 else [duration * part for part in (0.08, 0.34, 0.62, 0.9)]
            frames = []
            for position in positions:
                try:
                    result = subprocess.run(
                        [
                            "ffmpeg", "-hide_banner", "-loglevel", "error", "-ss", f"{position:.3f}",
                            "-i", str(source), "-frames:v", "1", "-vf", "scale=480:-2",
                            "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1",
                        ],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45,
                    )
                    if result.returncode == 0 and result.stdout:
                        with Image.open(io.BytesIO(result.stdout)) as frame:
                            frames.append(frame.convert("RGB").copy())
                except (OSError, subprocess.TimeoutExpired, UnidentifiedImageError):
                    continue
            if not frames:
                raise ValueError("FFmpeg could not create a representative video preview")
            cell_width = max(frame.width for frame in frames)
            cell_height = max(frame.height for frame in frames)
            sheet = Image.new("RGB", (cell_width * 2, cell_height * 2), (11, 14, 17))
            for index, frame in enumerate(frames[:4]):
                x = (index % 2) * cell_width + (cell_width - frame.width) // 2
                y = (index // 2) * cell_height + (cell_height - frame.height) // 2
                sheet.paste(frame, (x, y))
            sheet.save(destination, "JPEG", quality=86, optimize=True)
        else:
            with Image.open(source) as image:
                image = ImageOps.exif_transpose(image).convert("RGB")
                image.thumbnail((1200, 900), Image.Resampling.LANCZOS)
                image.save(destination, "JPEG", quality=86, optimize=True)
        destination.chmod(0o664)
        if os.geteuid() == 0:
            os.chown(destination, self.output_uid, self.output_gid)
        return destination

    def decide(self, file_id: int, decision: str) -> None:
        if decision not in {"keep", "reject", "undecided"}:
            raise ValueError("invalid decision")
        with connect(self.db_path) as db:
            db.execute("UPDATE files SET decision=?,updated_at=? WHERE id=?", (decision, utcnow(), file_id))

    def set_category(self, file_id: int, category: str) -> None:
        category = sanitize_component(category)[:100]
        with connect(self.db_path) as db:
            db.execute(
                "UPDATE files SET category=?,category_confidence=100,category_reason='manual override',updated_at=? WHERE id=?",
                (category, utcnow(), file_id),
            )

    def auto_decide_exact(self) -> int:
        with connect(self.db_path) as db:
            groups = [row[0] for row in db.execute("SELECT exact_group FROM files WHERE exact_group IS NOT NULL GROUP BY exact_group")]
            changed = 0
            for group_id in groups:
                members = db.execute("SELECT id FROM files WHERE exact_group=? ORDER BY quality_score DESC,LENGTH(path),path", (group_id,)).fetchall()
                for index, member in enumerate(members):
                    db.execute("UPDATE files SET decision=? WHERE id=?", ("keep" if index == 0 else "reject", member["id"]))
                    changed += 1
            db.commit()
        return changed

    def _safe_destination(self, root: Path, relative: str) -> Path:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._normalize_output_directories(destination.parent, root)
        if not destination.exists():
            return destination
        stem, suffix = destination.stem, destination.suffix
        for number in range(1, 10000):
            candidate = destination.with_name(f"{stem}__{number}{suffix}")
            if not candidate.exists():
                return candidate
        raise RuntimeError("too many destination name collisions")

    def _normalize_output_directories(self, directory: Path, root: Path) -> None:
        if os.geteuid() != 0:
            return
        current = directory
        while current == root or root in current.parents:
            os.chown(current, self.output_uid, self.output_gid)
            os.chmod(current, 0o775)
            if current == root:
                break
            current = current.parent

    def _normalize_output_file(self, path: Path) -> None:
        source_mode = stat_module.S_IMODE(path.stat().st_mode)
        if os.geteuid() == 0:
            os.chown(path, self.output_uid, self.output_gid)
        os.chmod(path, 0o664 | (source_mode & 0o111))

    def quarantine_file(self, file_id: int) -> str:
        if not self.allow_actions:
            raise PermissionError("Actions are disabled. Set ALLOW_ACTIONS=true and mount /source read/write.")
        row = self.get_file(file_id)
        if not row:
            raise FileNotFoundError("catalog row not found")
        source = Path(row["path"])
        destination = self._safe_destination(self.quarantine, row["relative_path"])
        shutil.move(str(source), str(destination))
        with connect(self.db_path) as db:
            db.execute("INSERT INTO actions(created_at,action,file_id,source_path,destination_path,status) VALUES(?,?,?,?,?,'complete')",
                       (utcnow(), "quarantine", file_id, str(source), str(destination)))
            db.execute("DELETE FROM files WHERE id=?", (file_id,))
            db.commit()
        return str(destination)

    def build_curated_library(self) -> dict:
        """Copies explicit keepers and ungrouped files. Never modifies the recovered source."""
        if not self.allow_actions:
            raise PermissionError("Actions are disabled. Set ALLOW_ACTIONS=true to build the curated output.")
        with connect(self.db_path) as db:
            review_skipped = db.execute(
                """SELECT COUNT(*) FROM files WHERE validation NOT IN ('zero','corrupt','unreadable')
                   AND decision='undecided' AND known_good_match=0
                   AND (exact_group IS NOT NULL OR similar_group IS NOT NULL)"""
            ).fetchone()[0]
            known_good_skipped = db.execute(
                """SELECT COUNT(*) FROM files WHERE validation NOT IN ('zero','corrupt','unreadable')
                   AND decision!='keep' AND known_good_match=1"""
            ).fetchone()[0]
            rows = db.execute(
                """SELECT * FROM files WHERE validation NOT IN ('zero','corrupt','unreadable')
                   AND (decision='keep' OR (decision='undecided' AND known_good_match=0
                        AND exact_group IS NULL AND similar_group IS NULL))
                   ORDER BY id"""
            ).fetchall()
            exported, failed = 0, 0
            for row in rows:
                if row["exported_path"] and Path(row["exported_path"]).exists():
                    continue
                source = Path(row["path"])
                category = sanitize_component(row["category"] or "Other Files")
                date_text = row["exif_date"] or row["filename_date"]
                year_month = "Unknown_Date"
                if date_text:
                    year_month = date_text[:7].replace("-", os.sep)
                relative = str(Path(category) / year_month / source.name)
                destination = self._safe_destination(self.output, relative)
                try:
                    shutil.copy2(source, destination)
                    metadata_fixed = False
                    if row["is_image"] and not row["exif_date"] and row["filename_date"] and row["date_confidence"] >= 85:
                        metadata_fixed = apply_date_metadata(destination, row["filename_date"])
                    self._normalize_output_file(destination)
                    db.execute("UPDATE files SET exported_path=? WHERE id=?", (str(destination), row["id"]))
                    db.execute(
                        "INSERT INTO actions(created_at,action,file_id,source_path,destination_path,status,detail) VALUES(?,?,?,?,?,'complete',?)",
                        (utcnow(), "export", row["id"], str(source), str(destination), "filename date applied" if metadata_fixed else "copied"),
                    )
                    exported += 1
                except Exception as exc:
                    failed += 1
                    db.execute(
                        "INSERT INTO actions(created_at,action,file_id,source_path,destination_path,status,detail) VALUES(?,?,?,?,?,'failed',?)",
                        (utcnow(), "export", row["id"], str(source), str(destination), str(exc)[:500]),
                    )
                if (exported + failed) % 50 == 0:
                    db.commit()
            db.commit()
        catalog = self.export_catalog(self.output)
        self.export_directory_catalog(self.output)
        return {
            "exported": exported, "failed": failed, "review_skipped": review_skipped,
            "known_good_skipped": known_good_skipped, "catalog": str(catalog),
        }

    def export_catalog(self, root: Path | None = None) -> Path:
        root = root or self.db_path.parent
        root.mkdir(parents=True, exist_ok=True)
        csv_path = root / "recovery_catalog.csv"
        jsonl_path = root / "recovery_catalog.jsonl"
        fields = [
            "id", "relative_path", "name", "extension", "size", "mtime_ns", "ctime_ns", "mode", "uid", "gid",
            "evidence_role", "mime", "validation", "validation_detail",
            "content_hash", "width", "height", "megapixels", "phash", "exif_date", "filename_date",
            "date_confidence", "date_reason", "category", "category_confidence", "category_reason",
            "quality_score", "exact_group", "similar_group", "known_good_match", "known_good_count",
            "known_good_library", "known_good_path", "decision", "exported_path",
            "ai_caption", "ai_people", "ai_objects", "ai_ocr_text", "ai_tags", "ai_model", "ai_updated_at",
            "media_kind", "media_origin", "sensitivity", "video_duration", "video_width", "video_height",
            "video_fps", "video_codec", "audio_codec", "video_creation_date", "video_analysis_version",
        ]
        with connect(self.db_path) as db, csv_path.open("w", newline="", encoding="utf-8") as csv_file, jsonl_path.open("w", encoding="utf-8") as json_file:
            writer = csv.DictWriter(csv_file, fieldnames=fields)
            writer.writeheader()
            for row in db.execute("SELECT * FROM files ORDER BY id"):
                item = {field: row[field] if field in row.keys() else "" for field in fields}
                item["evidence_role"] = "zero_byte_placeholder" if row["size"] == 0 else "content_file"
                writer.writerow(item)
                json_file.write(json.dumps(item, ensure_ascii=False) + "\n")
        if root.resolve() == self.output:
            self._normalize_output_file(csv_path)
            self._normalize_output_file(jsonl_path)
        return csv_path

    def export_reconstruction_catalogs(self, root: Path | None = None) -> list[Path]:
        root = root or self.db_path.parent
        root.mkdir(parents=True, exist_ok=True)
        exports = {
            "reconstruction_plan": """SELECT p.*,f.relative_path source_relative_path,f.name,f.size,
                                               f.media_kind,f.media_origin,f.sensitivity
                                        FROM reconstruction_proposals p JOIN files f ON f.id=p.file_id
                                        ORDER BY p.file_id""",
            "folder_context": "SELECT * FROM folder_context ORDER BY suggestion_score DESC,directory_id",
            "reconstruction_directories": "SELECT * FROM reconstruction_directories ORDER BY directory_id",
            "known_good_matches": "SELECT * FROM known_good_matches ORDER BY file_id,library,relative_path",
            "file_relationships": "SELECT * FROM file_relationships ORDER BY file_id,relationship,related_file_id",
            "file_facets": "SELECT * FROM file_facets ORDER BY file_id,facet_type,source,value",
            "recovery_context": "SELECT * FROM recovery_context ORDER BY context_type,label,id",
            "review_questions": "SELECT * FROM review_questions ORDER BY status,id",
            "ai_structure_suggestions": "SELECT * FROM ai_structure_suggestions ORDER BY status,id",
        }
        written = []
        with connect(self.db_path) as db:
            for name, query in exports.items():
                csv_path = root / f"{name}.csv"
                jsonl_path = root / f"{name}.jsonl"
                cursor = db.execute(query)
                fields = [item[0] for item in cursor.description]
                with csv_path.open("w", newline="", encoding="utf-8") as csv_file, jsonl_path.open("w", encoding="utf-8") as json_file:
                    writer = csv.DictWriter(csv_file, fieldnames=fields)
                    writer.writeheader()
                    for row in cursor:
                        item = {field: row[field] for field in fields}
                        writer.writerow(item)
                        json_file.write(json.dumps(item, ensure_ascii=False) + "\n")
                written.extend((csv_path, jsonl_path))
        if root.resolve() == self.output:
            for path in written:
                self._normalize_output_file(path)
        return written

    def export_directory_catalog(self, root: Path | None = None) -> Path:
        root = root or self.db_path.parent
        root.mkdir(parents=True, exist_ok=True)
        csv_path = root / "directory_catalog.csv"
        jsonl_path = root / "directory_catalog.jsonl"
        fields = [
            "id", "relative_path", "parent_relative_path", "name", "mtime_ns", "ctime_ns",
            "mode", "uid", "gid", "status", "read_error", "updated_at",
        ]
        with connect(self.db_path) as db, csv_path.open("w", newline="", encoding="utf-8") as csv_file, jsonl_path.open("w", encoding="utf-8") as json_file:
            writer = csv.DictWriter(csv_file, fieldnames=fields)
            writer.writeheader()
            for row in db.execute("SELECT * FROM directories ORDER BY relative_path"):
                item = {field: row[field] if field in row.keys() else "" for field in fields}
                writer.writerow(item)
                json_file.write(json.dumps(item, ensure_ascii=False) + "\n")
        if root.resolve() == self.output:
            self._normalize_output_file(csv_path)
            self._normalize_output_file(jsonl_path)
        return csv_path


def apply_date_metadata(path: Path, iso_date: str) -> bool:
    try:
        value = dt.datetime.fromisoformat(iso_date).strftime("%Y:%m:%d %H:%M:%S")
        result = subprocess.run(
            ["exiftool", "-overwrite_original", f"-DateTimeOriginal={value}", f"-CreateDate={value}", f"-ModifyDate={value}", str(path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60,
        )
        return result.returncode == 0
    except Exception:
        return False


def sanitize_component(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._ -]+", "_", value).strip(" .")
    return cleaned or "Uncategorized"


def human_bytes(value: int) -> str:
    amount = float(value or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if amount < 1024 or unit == "PiB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} PiB"
