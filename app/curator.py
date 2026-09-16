from __future__ import annotations

import csv
import datetime as dt
import json
import math
import mimetypes
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
import warnings
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from email.parser import BytesHeaderParser
from pathlib import Path

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
OFFICE_MARKERS = {
    ".docx": "word/document.xml",
    ".xlsx": "xl/workbook.xml",
    ".pptx": "ppt/presentation.xml",
}
CAMERA_PREFIXES = ("img_", "dsc_", "dscf", "pxl_", "mvimg_", "100_", "sam_")
SCREENSHOT_WORDS = ("screenshot", "screen shot", "screencap", "snip", "capture")
DOWNLOAD_WORDS = ("download", "received", "messenger", "whatsapp", "telegram")
THUMB_WORDS = ("thumb", "thumbnail", "preview", "cache", "tmp", "temp")


@dataclass
class DateProposal:
    value: str | None = None
    source: str | None = None
    confidence: int = 0
    reason: str | None = None


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
              decision TEXT DEFAULT 'undecided',
              exported_path TEXT,
              ai_caption TEXT,
              ai_people TEXT,
              ai_objects TEXT,
              ai_ocr_text TEXT,
              ai_tags TEXT,
              ai_model TEXT,
              ai_updated_at TEXT,
              updated_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_files_size ON files(size);
            CREATE INDEX IF NOT EXISTS idx_files_hash ON files(content_hash);
            CREATE INDEX IF NOT EXISTS idx_files_exact ON files(exact_group);
            CREATE INDEX IF NOT EXISTS idx_files_similar ON files(similar_group);
            CREATE INDEX IF NOT EXISTS idx_files_category ON files(category);
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
        for column in ("ai_caption", "ai_people", "ai_objects", "ai_ocr_text", "ai_tags", "ai_model", "ai_updated_at"):
            if column not in existing_columns:
                db.execute(f"ALTER TABLE files ADD COLUMN {column} TEXT")


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


def iter_source_files(root: Path):
    """Traverse without materializing every pathname or following directory symlinks."""
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            yield Path(entry.path)
                    except OSError:
                        continue
        except OSError:
            continue


def analyze_record(record: dict) -> dict:
    """Worker-safe file analysis. Database writes remain in the coordinator thread."""
    path = Path(record["path"])
    extension = record.get("extension") or ""
    mime = sniff_mime(path) if record["size"] else "application/x-empty"
    detected_extension = infer_extension(mime)
    date_proposal = parse_filename_date(path.name)
    if record["size"] == 0:
        metadata = {"validation": "zero", "validation_detail": "zero-byte file", "is_image": 0}
    elif extension in RAW_EXTENSIONS:
        metadata = analyze_raw(path)
    elif extension in IMAGE_EXTENSIONS or mime.startswith("image/"):
        metadata = analyze_image(path)
    else:
        validation, detail = validate_nonimage(path, extension)
        metadata = {"validation": validation, "validation_detail": detail, "is_image": 0}
    category, category_confidence, category_reason = categorize(path, metadata)
    score = quality_score(path, metadata)
    if not metadata.get("exif_date") and date_proposal.value:
        score += 8
    return {
        "id": record["id"], "mime": mime, "detected_extension": detected_extension,
        **metadata, "filename_date": date_proposal.value, "date_confidence": date_proposal.confidence,
        "date_reason": date_proposal.reason, "category": category,
        "category_confidence": category_confidence, "category_reason": category_reason,
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
    ):
        self.source = source.resolve()
        self.output = output.resolve()
        self.quarantine = quarantine.resolve()
        self.db_path = db_path
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

    def _scan_wrapper(self) -> None:
        try:
            self.scan()
            self._set_state(running=False, phase="complete", message="Scan complete")
        except ScanCancelled as exc:
            self._set_state(running=False, phase="stopped", message=str(exc), error=None)
        except Exception as exc:
            self._set_state(running=False, phase="failed", message="Scan failed", error=str(exc))

    def scan(self) -> None:
        if not self.source.exists():
            raise FileNotFoundError(f"Source path does not exist: {self.source}")
        scan_token = utcnow() + "-" + os.urandom(4).hex()
        self._begin_phase("inventory", 0, "Inventorying files with bounded memory")
        with connect(self.db_path) as db:
            inventory_count = 0
            for index, path in enumerate(iter_source_files(self.source), 1):
                try:
                    stat = path.stat()
                except OSError:
                    continue
                inventory_count = index
                relative = str(path.relative_to(self.source))
                existing = db.execute("SELECT size,mtime_ns FROM files WHERE path=?", (str(path),)).fetchone()
                changed = not existing or existing["size"] != stat.st_size or existing["mtime_ns"] != stat.st_mtime_ns
                db.execute(
                    """INSERT INTO files(path,relative_path,name,extension,size,mtime_ns,seen_scan,updated_at)
                       VALUES(?,?,?,?,?,?,?,?)
                       ON CONFLICT(path) DO UPDATE SET relative_path=excluded.relative_path,name=excluded.name,
                         extension=excluded.extension,size=excluded.size,mtime_ns=excluded.mtime_ns,
                         seen_scan=excluded.seen_scan,updated_at=excluded.updated_at""",
                    (str(path), relative, path.name, path.suffix.lower(), stat.st_size, stat.st_mtime_ns, scan_token, utcnow()),
                )
                if changed:
                    db.execute(
                        """UPDATE files SET mime=NULL,detected_extension=NULL,validation='unchecked',validation_detail=NULL,
                           content_hash=NULL,is_image=0,width=NULL,height=NULL,megapixels=NULL,phash=NULL,exif_date=NULL,
                           exif_make=NULL,exif_model=NULL,filename_date=NULL,date_confidence=0,date_reason=NULL,
                           category=NULL,category_confidence=0,category_reason=NULL,quality_score=0,exact_group=NULL,
                           similar_group=NULL,decision='undecided',exported_path=NULL,ai_caption=NULL,ai_people=NULL,
                           ai_objects=NULL,ai_ocr_text=NULL,ai_tags=NULL,ai_model=NULL,ai_updated_at=NULL WHERE path=?""", (str(path),)
                    )
                if index % self.batch_size == 0:
                    db.commit()
                    self._progress(index, index, f"Inventorying files — {index:,} found")
                    self._check_cancel()
            db.execute("DELETE FROM files WHERE seen_scan IS NULL OR seen_scan != ?", (scan_token,))
            db.commit()
            self._progress(inventory_count, inventory_count, f"Inventory complete — {inventory_count:,} files")

            self._analyze_pending(db)
            self._hash_candidates(db)
            db.execute("UPDATE files SET exact_group=NULL")
            db.execute(
                """UPDATE files SET exact_group=content_hash WHERE content_hash IN
                   (SELECT content_hash FROM files WHERE content_hash IS NOT NULL GROUP BY content_hash HAVING COUNT(*)>1)"""
            )
            db.commit()

        self._build_similar_groups(self.similarity_radius)
        self.export_catalog()

    def _analyze_pending(self, db: sqlite3.Connection) -> None:
        total = db.execute("SELECT COUNT(*) FROM files WHERE mime IS NULL").fetchone()[0]
        self._begin_phase(
            "analysis", total,
            f"Validating and classifying files with {self.analysis_workers} worker(s)",
        )
        processed = 0
        while True:
            self._check_cancel()
            rows = [dict(row) for row in db.execute(
                "SELECT * FROM files WHERE mime IS NULL ORDER BY id LIMIT ?", (self.batch_size,)
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
                        }
                    db.execute(
                        """UPDATE files SET mime=?,detected_extension=?,validation=?,validation_detail=?,is_image=?,
                           width=?,height=?,megapixels=?,phash=?,exif_date=?,exif_make=?,exif_model=?,filename_date=?,
                           date_confidence=?,date_reason=?,category=?,category_confidence=?,category_reason=?,quality_score=?,updated_at=?
                           WHERE id=?""",
                        (result["mime"], result["detected_extension"], result.get("validation"), result.get("validation_detail"),
                         result.get("is_image", 0), result.get("width"), result.get("height"), result.get("megapixels"),
                         result.get("phash"), result.get("exif_date"), result.get("exif_make"), result.get("exif_model"),
                         result.get("filename_date"), result.get("date_confidence", 0), result.get("date_reason"),
                         result.get("category"), result.get("category_confidence", 0), result.get("category_reason"),
                         result.get("quality_score", 0), utcnow(), result["id"]),
                    )
            db.commit()
            processed += len(rows)
            self._progress(processed, total)

    def _hash_candidates(self, db: sqlite3.Connection) -> None:
        candidate_join = """JOIN (SELECT size FROM files WHERE size>0 GROUP BY size HAVING COUNT(*)>1) d
                            ON d.size=f.size"""
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

    def _build_similar_groups(self, radius: int = 6) -> None:
        with connect(self.db_path) as db:
            total = db.execute("SELECT COUNT(*) FROM files WHERE phash IS NOT NULL AND validation='valid'").fetchone()[0]
            self._begin_phase("similarity", total, "Indexing visually similar images without all-pairs comparisons")
            tree = BKTree()
            hash_to_ids: dict[int, list[int]] = defaultdict(list)
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
                    for neighbor in tree.search(value, radius):
                        for other_id in hash_to_ids[neighbor]:
                            left = dimensions[row["id"]]
                            right = dimensions[other_id]
                            left_ratio = left[0] / max(left[1], 1)
                            right_ratio = right[0] / max(right[1], 1)
                            if abs(math.log(max(left_ratio, 0.001) / max(right_ratio, 0.001))) <= 0.12:
                                union.union(row["id"], other_id)
                    tree.add(value)
                    hash_to_ids[value].append(row["id"])
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
                   SUM(is_image=1) images,SUM(exact_group IS NOT NULL) exact_members,
                   COUNT(DISTINCT exact_group) exact_groups,COUNT(DISTINCT similar_group) similar_groups,
                   SUM(filename_date IS NOT NULL AND exif_date IS NULL) date_proposals
                   FROM files"""
            ).fetchone()
            categories = [dict(item) for item in db.execute("SELECT category,COUNT(*) count FROM files GROUP BY category ORDER BY count DESC")]
        result = dict(row)
        result["categories"] = categories
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

    def list_files(self, category: str | None = None, validation: str | None = None, limit: int = 500) -> list[dict]:
        clauses, params = [], []
        if category:
            clauses.append("category=?")
            params.append(category)
        if validation:
            clauses.append("validation=?")
            params.append(validation)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(limit)
        with connect(self.db_path) as db:
            return [dict(row) for row in db.execute(f"SELECT * FROM files{where} ORDER BY quality_score DESC,id LIMIT ?", params)]

    def get_file(self, file_id: int) -> sqlite3.Row | None:
        with connect(self.db_path) as db:
            return db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()

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
        if not destination.exists():
            return destination
        stem, suffix = destination.stem, destination.suffix
        for number in range(1, 10000):
            candidate = destination.with_name(f"{stem}__{number}{suffix}")
            if not candidate.exists():
                return candidate
        raise RuntimeError("too many destination name collisions")

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
                   AND decision='undecided' AND (exact_group IS NOT NULL OR similar_group IS NOT NULL)"""
            ).fetchone()[0]
            rows = db.execute(
                """SELECT * FROM files WHERE validation NOT IN ('zero','corrupt','unreadable')
                   AND (decision='keep' OR (decision='undecided' AND exact_group IS NULL AND similar_group IS NULL))
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
        return {"exported": exported, "failed": failed, "review_skipped": review_skipped, "catalog": str(catalog)}

    def export_catalog(self, root: Path | None = None) -> Path:
        root = root or self.db_path.parent
        root.mkdir(parents=True, exist_ok=True)
        csv_path = root / "recovery_catalog.csv"
        jsonl_path = root / "recovery_catalog.jsonl"
        fields = [
            "id", "relative_path", "name", "extension", "size", "mime", "validation", "validation_detail",
            "content_hash", "width", "height", "megapixels", "phash", "exif_date", "filename_date",
            "date_confidence", "date_reason", "category", "category_confidence", "category_reason",
            "quality_score", "exact_group", "similar_group", "decision", "exported_path",
            "ai_caption", "ai_people", "ai_objects", "ai_ocr_text", "ai_tags", "ai_model", "ai_updated_at",
        ]
        with connect(self.db_path) as db, csv_path.open("w", newline="", encoding="utf-8") as csv_file, jsonl_path.open("w", encoding="utf-8") as json_file:
            writer = csv.DictWriter(csv_file, fieldnames=fields)
            writer.writeheader()
            for row in db.execute("SELECT * FROM files ORDER BY id"):
                item = {field: row[field] if field in row.keys() else "" for field in fields}
                writer.writerow(item)
                json_file.write(json.dumps(item, ensure_ascii=False) + "\n")
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
