import os
import csv
import datetime as dt
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from PIL import Image

from app.ai import AIProviderClient, AIProviderResponseError, ProviderConfig
from app.curator import IMAGE_ANALYSIS_VERSION, Curator, connect, extract_exif_gps, parse_filename_date


class CuratorTests(unittest.TestCase):
    def test_filename_date_is_conservative(self):
        parsed = parse_filename_date("IMG_20230517_142233.jpg")
        self.assertEqual(parsed.value, "2023-05-17T14:22:33")
        self.assertGreaterEqual(parsed.confidence, 90)
        self.assertIsNone(parse_filename_date("vacation_03-04-21.jpg").value)
        self.assertIsNone(parse_filename_date("IMG_20230231_120000.jpg").value)

    def test_exif_gps_coordinates_are_normalized(self):
        latitude, longitude, altitude = extract_exif_gps({
            34853: {
                1: "N", 2: (40, 42, 46.8),
                3: "W", 4: (74, 0, 21.6),
                5: 0, 6: 12.5,
            },
        })
        self.assertAlmostEqual(latitude, 40.713, places=6)
        self.assertAlmostEqual(longitude, -74.006, places=6)
        self.assertEqual(altitude, 12.5)

    def test_photo_metadata_context_and_search_use_dates_cameras_and_rounded_gps(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            Image.new("RGB", (120, 80), (30, 60, 90)).save(source / "trip.jpg")
            Image.new("RGB", (120, 80), (90, 60, 30)).save(source / "other.jpg")
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.scan()
            with connect(config / "catalog.sqlite3") as db:
                db.execute(
                    """UPDATE files SET exif_date='2021-07-04T14:30:00',exif_make='Apple',
                              exif_model='iPhone 12',exif_lens_model='Wide Camera',
                              exif_software='iOS 14',exif_latitude=40.71281,exif_longitude=-74.00602
                       WHERE name='trip.jpg'"""
                )
                db.commit()

            context = curator._curation_conversation_context()
            metadata = context["photo_metadata"]
            self.assertEqual(metadata["coverage"]["photos_with_embedded_date"], 1)
            self.assertEqual(metadata["coverage"]["photos_with_gps"], 1)
            self.assertEqual(metadata["camera_models"][0]["camera"], "Apple iPhone 12")
            self.assertEqual(metadata["gps_areas"][0]["gps_area"], "40.71,-74.01")
            sample = next(item for item in context["representative_samples"] if item["name"] == "trip.jpg")
            self.assertEqual(sample["date_source"], "embedded_photo")
            self.assertEqual(sample["gps_area"], "40.71,-74.01")

            result = curator._catalog_search_for_curation({
                "all": [
                    {"field": "capture_date", "operator": "starts_with", "value": "2021-07"},
                    {"field": "gps_area", "operator": "equals", "value": "40.71,-74.01"},
                    {"field": "camera_model", "operator": "equals", "value": "iPhone 12"},
                ],
            }, "July NYC photos")
            self.assertEqual(result["matches"], 1)
            self.assertEqual(result["examples"][0]["date_source"], "embedded_photo")
            self.assertEqual(result["gps_areas"], [{"value": "40.71,-74.01", "count": 1}])

            with connect(config / "catalog.sqlite3") as db:
                db.execute("UPDATE files SET image_analysis_version=0 WHERE name='other.jpg'")
                db.commit()
            curator.scan()
            with connect(config / "catalog.sqlite3") as db:
                version = db.execute(
                    "SELECT image_analysis_version FROM files WHERE name='other.jpg'"
                ).fetchone()[0]
            self.assertEqual(version, IMAGE_ANALYSIS_VERSION)

    def test_scan_groups_and_catalog(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (root / name for name in ("source", "output", "quarantine", "config"))
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            image = Image.new("RGB", (1200, 800), (90, 130, 180))
            image.save(source / "IMG_20230517_142233.jpg", quality=95)
            (source / "duplicate.jpg").write_bytes((source / "IMG_20230517_142233.jpg").read_bytes())
            image.resize((300, 200)).save(source / "thumbnail_20230517.jpg", quality=70)
            (source / "empty.pdf").write_bytes(b"")
            (source / "broken.jpg").write_bytes(b"not an image")
            (source / "Original Empty Folder").mkdir()

            curator = Curator(source, output, quarantine, config / "catalog.sqlite3", allow_actions=True)
            curator.scan()
            summary = curator.summary()
            self.assertEqual(summary["files"], 5)
            self.assertEqual(summary["zero_files"], 1)
            self.assertEqual(summary["corrupt_files"], 1)
            self.assertEqual(summary["exact_groups"], 1)
            self.assertGreaterEqual(summary["similar_groups"], 1)
            self.assertGreaterEqual(summary["date_proposals"], 1)
            self.assertEqual(summary["directories"], 2)
            self.assertTrue((config / "recovery_catalog.csv").exists())
            self.assertTrue((config / "directory_catalog.csv").exists())

            with (config / "recovery_catalog.csv").open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            zero_row = next(row for row in rows if row["name"] == "empty.pdf")
            self.assertEqual(zero_row["evidence_role"], "zero_byte_placeholder")
            self.assertTrue(zero_row["mtime_ns"])

            curator.auto_decide_exact()
            result = curator.build_curated_library()
            self.assertGreaterEqual(result["exported"], 1)
            self.assertGreaterEqual(result["review_skipped"], 1)
            self.assertTrue((output / "recovery_catalog.jsonl").exists())
            self.assertTrue((output / "directory_catalog.jsonl").exists())
            if os.geteuid() == 0:
                exported = next(path for path in output.rglob("*") if path.is_file() and path.suffix == ".jpg")
                exported_stat = exported.stat()
                self.assertEqual((exported_stat.st_uid, exported_stat.st_gid), (os.geteuid(), os.getegid()))
                self.assertEqual(stat.S_IMODE(exported_stat.st_mode) & 0o664, 0o664)

            # Unchanged records must resume from SQLite without repeating expensive analysis.
            with patch("app.curator.analyze_record", side_effect=AssertionError("unchanged file was re-analyzed")):
                curator.scan()

    def test_large_inventory_is_batched_and_stoppable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (root / name for name in ("source", "output", "quarantine", "config"))
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            for number in range(500):
                (source / f"zero-{number:04d}.dat").touch()
            curator = Curator(
                source, output, quarantine, config / "catalog.sqlite3",
                analysis_workers=2, hash_workers=1, batch_size=16,
            )
            curator.scan()
            self.assertEqual(curator.summary()["files"], 500)
            self.assertEqual(curator.summary()["zero_files"], 500)

    def test_large_identical_visual_bucket_uses_one_group(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (root / name for name in ("source", "output", "quarantine", "config"))
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            sample = source / "sample.png"
            Image.new("RGB", (64, 64), (40, 80, 120)).save(sample)
            payload = sample.read_bytes()
            for number in range(100):
                (source / f"copy-{number:03d}.png").write_bytes(payload)
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3", batch_size=16)
            curator.scan()
            summary = curator.summary()
            self.assertEqual(summary["files"], 101)
            self.assertEqual(summary["exact_groups"], 1)
            self.assertEqual(summary["similar_groups"], 1)

    def test_known_good_folder_selection_and_exact_matching(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config, known_good = (
                root / name for name in ("source", "output", "quarantine", "config", "known-good")
            )
            for directory in (source, output, quarantine, config, known_good):
                directory.mkdir()
            backup_one = known_good / "Backup One"
            backup_two = known_good / "Backup Two"
            backup_one.mkdir()
            backup_two.mkdir()

            first_payload = b"trusted-photo-one" * 17
            second_payload = b"trusted-document-two" * 23
            unmatched_payload = b"recovered-only" * 31
            (source / "recovered-photo-copy.bin").write_bytes(first_payload)
            (source / "recovered-document-copy.bin").write_bytes(second_payload)
            (source / "recovered-only.txt").write_bytes(unmatched_payload)
            (backup_one / "original-photo.bin").write_bytes(first_payload)
            (backup_two / "second-trusted-photo.bin").write_bytes(first_payload)
            (backup_two / "original-document.bin").write_bytes(second_payload)
            (backup_two / "no-recovery-counterpart.bin").write_bytes(b"unique-known-good-size")

            curator = Curator(
                source, output, quarantine, config / "catalog.sqlite3",
                allow_actions=True, reference_root=known_good,
            )
            curator.add_reference_selection("Backup One")
            curator.add_reference_selection("Backup Two")
            curator.scan()

            summary = curator.summary()
            self.assertEqual(summary["known_good_matches"], 2)
            self.assertEqual(summary["reference_files"], 4)
            self.assertEqual(len(summary["reference_selections"]), 2)
            matches = curator.list_files(known_good=True)
            self.assertEqual(
                {item["name"] for item in matches},
                {"recovered-photo-copy.bin", "recovered-document-copy.bin"},
            )
            self.assertTrue(all(item["known_good_path"] for item in matches))
            photo_match = next(item for item in matches if item["name"] == "recovered-photo-copy.bin")
            self.assertEqual(photo_match["known_good_count"], 2)

            with connect(config / "catalog.sqlite3") as db:
                decoy = db.execute(
                    "SELECT content_hash FROM reference_files WHERE path LIKE '%no-recovery-counterpart.bin'"
                ).fetchone()
                self.assertIsNone(decoy["content_hash"])
                path_matches = db.execute(
                    "SELECT COUNT(*) FROM known_good_matches WHERE file_id=?", (photo_match["id"],)
                ).fetchone()[0]
                self.assertEqual(path_matches, 2)

            result = curator.build_curated_library()
            self.assertEqual(result["known_good_skipped"], 2)
            self.assertEqual(result["exported"], 1)
            self.assertTrue(any(path.name == "recovered-only.txt" for path in output.rglob("*")))

            curator.decide(matches[0]["id"], "keep")
            result = curator.build_curated_library()
            self.assertEqual(result["exported"], 1)

    def test_sanitization_build_omits_known_good_and_exact_duplicates_and_uses_safe_links(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config, known_good = (
                root / name for name in ("source", "output", "quarantine", "config", "known-good")
            )
            for directory in (source, output, quarantine, config, known_good):
                directory.mkdir()
            trusted = known_good / "Trusted"
            trusted.mkdir()
            trusted_payload = b"already safely backed up"
            (trusted / "trusted-original.bin").write_bytes(trusted_payload)
            (source / "known-good-copy.bin").write_bytes(trusted_payload)
            plain = source / "plain.bin"
            plain.write_bytes(b"unique unchanged content")

            dated = source / "IMG_20220102_030405.jpg"
            Image.new("RGB", (80, 60), (25, 80, 140)).save(dated)
            duplicate_folder = source / "duplicates"
            duplicate_folder.mkdir()
            (duplicate_folder / "copy.jpg").write_bytes(dated.read_bytes())
            (source / "empty" / "original" / "folders").mkdir(parents=True)

            live_folder = source / "surviving"
            zero_folder = source / "placeholders"
            live_folder.mkdir()
            zero_folder.mkdir()
            live = live_folder / "legacy-name.jpg"
            placeholder = zero_folder / "legacy-name.jpg"
            Image.new("RGB", (90, 70), (80, 30, 20)).save(live)
            placeholder.touch()
            recovered_timestamp = int(dt.datetime(2018, 4, 5, 12, 30, tzinfo=dt.timezone.utc).timestamp())
            os.utime(placeholder, (recovered_timestamp, recovered_timestamp))

            curator = Curator(
                source, output, quarantine, config / "catalog.sqlite3",
                allow_actions=True, reference_root=known_good,
            )
            curator.add_reference_selection("Trusted")
            curator.scan()
            preview = curator.build_sanitization_foundation()

            self.assertEqual(preview["known_good_excluded"], 1)
            self.assertEqual(preview["duplicate_excluded"], 1)
            self.assertEqual(preview["zero_evidence"], 1)
            self.assertEqual(preview["included"], 3)
            self.assertGreaterEqual(preview["repair_candidates"], 2)
            self.assertGreaterEqual(preview["zero_date_repairs"], 1)
            self.assertTrue(preview["same_filesystem"])

            authorized = curator.sanitization_preview(authorize=True)
            with patch("app.curator.apply_missing_exif_metadata", return_value=True):
                result = curator.export_sanitized_library(
                    authorized["token"], allow_copy_fallback=True,
                )
            self.assertEqual(result["failed"], 0)
            self.assertGreaterEqual(result["hardlinked"], 1)
            self.assertGreaterEqual(result["repaired"], 2)
            self.assertTrue((output / "sanitization_manifest.csv").is_file())
            self.assertTrue((output / "sanitization_exclusions.csv").is_file())
            self.assertFalse((output / "known-good-copy.bin").exists())
            self.assertEqual(len(list(output.rglob("*.jpg"))), 2)
            self.assertTrue((output / "empty" / "original" / "folders").is_dir())
            self.assertTrue((output / "duplicates").is_dir())
            self.assertTrue((output / "placeholders").is_dir())
            self.assertFalse((output / "placeholders" / "legacy-name.jpg").exists())
            self.assertFalse((output / "Photos").exists())

            plain_export = output / "plain.bin"
            self.assertEqual(plain.stat().st_ino, plain_export.stat().st_ino)
            legacy_export = output / "surviving" / "legacy-name.jpg"
            self.assertNotEqual(live.stat().st_ino, legacy_export.stat().st_ino)
            self.assertEqual(int(legacy_export.stat().st_mtime), recovered_timestamp)

            overview = curator.sanitization_overview()
            self.assertFalse(overview["authorized"])
            self.assertEqual(overview["included"], 3)

    def test_sanitization_omits_only_strict_smaller_photo_and_inherits_missing_exif(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            album = source / "Recovered Album" / "Day One"
            album.mkdir(parents=True)
            larger = album / "photo-large.jpg"
            smaller = album / "photo-small.jpg"
            different = album / "different-color.jpg"
            Image.new("RGB", (800, 600), (40, 90, 150)).save(larger, quality=92)
            Image.new("RGB", (400, 300), (40, 90, 150)).save(smaller, quality=75)
            Image.new("RGB", (400, 300), (180, 35, 25)).save(different, quality=75)

            curator = Curator(
                source, output, quarantine, config / "catalog.sqlite3", allow_actions=True,
            )
            curator.scan()
            with connect(curator.db_path) as db:
                db.execute(
                    """UPDATE files SET exif_date='2019-06-07T08:09:10',exif_make='Example Camera',
                              exif_model='Pocket One',exif_latitude=42.35,exif_longitude=-71.06
                         WHERE relative_path='Recovered Album/Day One/photo-small.jpg'"""
                )
                db.commit()

            preview = curator.build_sanitization_foundation()
            self.assertEqual(preview["derivative_excluded"], 1)
            self.assertEqual(preview["included"], 2)
            self.assertEqual(preview["repair_candidates"], 1)
            authorized = curator.sanitization_preview(authorize=True)
            with patch("app.curator.apply_missing_exif_metadata", return_value=True) as apply_metadata:
                result = curator.export_sanitized_library(
                    authorized["token"], allow_copy_fallback=True,
                )
            self.assertEqual(result["failed"], 0)
            self.assertTrue((output / "Recovered Album" / "Day One" / "photo-large.jpg").is_file())
            self.assertFalse((output / "Recovered Album" / "Day One" / "photo-small.jpg").exists())
            self.assertTrue((output / "Recovered Album" / "Day One" / "different-color.jpg").is_file())
            self.assertNotEqual(
                larger.stat().st_ino,
                (output / "Recovered Album" / "Day One" / "photo-large.jpg").stat().st_ino,
            )
            repaired = apply_metadata.call_args.args[1]
            self.assertEqual(repaired["exif_date"], "2019-06-07T08:09:10")
            self.assertEqual(repaired["exif_make"], "Example Camera")
            self.assertEqual(repaired["exif_model"], "Pocket One")
            self.assertAlmostEqual(repaired["exif_latitude"], 42.35)
            self.assertAlmostEqual(repaired["exif_longitude"], -71.06)
            with (output / "sanitization_exclusions.csv").open(newline="", encoding="utf-8") as stream:
                exclusions = list(csv.DictReader(stream))
            smaller_record = next(item for item in exclusions if item["relative_path"].endswith("photo-small.jpg"))
            self.assertEqual(smaller_record["exclusion_reason"], "strict_lower_resolution_copy")
            self.assertTrue(smaller_record["keeper_relative_path"].endswith("photo-large.jpg"))

    def test_sanitization_rejects_output_nested_in_recovered_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            output = source / "curated-output"
            quarantine = root / "quarantine"
            config = root / "config"
            for directory in (source, output, quarantine, config):
                directory.mkdir(parents=True, exist_ok=True)
            (source / "recovered.txt").write_text("recovered", encoding="utf-8")
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            with self.assertRaisesRegex(ValueError, "separate folder"):
                curator.scan()

    def test_reset_catalog_preserves_library_files_but_clears_active_scan_settings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config, known_good = (
                root / name for name in ("source", "output", "quarantine", "config", "known-good")
            )
            for directory in (source, output, quarantine, config, known_good):
                directory.mkdir()
            backup = known_good / "Trusted"
            backup.mkdir()
            source_file = source / "recovered.txt"
            reference_file = backup / "trusted.txt"
            source_file.write_bytes(b"same bytes")
            reference_file.write_bytes(b"same bytes")

            curator = Curator(
                source, output, quarantine, config / "catalog.sqlite3", reference_root=known_good,
            )
            curator.add_reference_selection("Trusted")
            curator.scan()
            self.assertEqual(curator.summary()["known_good_matches"], 1)

            result = curator.reset_catalog()
            self.assertEqual(result["files"], 1)
            self.assertEqual(result["directories"], 1)
            self.assertEqual(curator.summary()["files"], 0)
            self.assertEqual(curator.summary()["directories"], 0)
            self.assertEqual(curator.summary()["reference_files"], 0)
            self.assertEqual(curator.selected_references(), [])
            self.assertTrue(source_file.exists())
            self.assertTrue(reference_file.exists())
            self.assertFalse((config / "recovery_catalog.csv").exists())

    def test_known_good_browser_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config, known_good = (
                root / name for name in ("source", "output", "quarantine", "config", "known-good")
            )
            for directory in (source, output, quarantine, config, known_good):
                directory.mkdir()
            curator = Curator(
                source, output, quarantine, config / "catalog.sqlite3", reference_root=known_good,
            )
            with self.assertRaises(ValueError):
                curator.add_reference_selection("../source")

    def test_empty_source_stops_before_known_good_and_preserves_catalog(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config, known_good = (
                root / name for name in ("source", "output", "quarantine", "config", "known-good")
            )
            for directory in (source, output, quarantine, config, known_good):
                directory.mkdir()
            trusted = known_good / "Trusted"
            trusted.mkdir()
            recovered = source / "recovered.bin"
            recovered.write_bytes(b"recovered file")

            curator = Curator(
                source, output, quarantine, config / "catalog.sqlite3", reference_root=known_good,
            )
            curator.add_reference_selection("Trusted")
            curator.scan()
            self.assertEqual(curator.summary()["files"], 1)
            self.assertEqual(curator.summary()["reference_files"], 0)

            recovered.unlink()
            (trusted / "new-reference.bin").write_bytes(b"known good")
            with self.assertRaisesRegex(RuntimeError, "No recovered files are visible"):
                curator.scan()

            self.assertEqual(curator.summary()["files"], 1)
            self.assertEqual(curator.summary()["reference_files"], 0)
            diagnostic = curator.source_diagnostic()
            self.assertTrue(diagnostic["readable"])
            self.assertFalse(diagnostic["has_entries"])

    def test_windows_system_volume_information_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            (source / "photo.jpg").write_bytes(b"not really a photo")
            system_folder = source / "System Volume Information"
            system_folder.mkdir()
            (system_folder / "tracking.log").write_bytes(b"system metadata")

            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            result = curator.scan()

            self.assertEqual(curator.summary()["files"], 1)
            self.assertEqual(result["ignored_system_directories"], 1)
            self.assertEqual(result["source_read_errors"], 0)

    def test_partial_source_read_errors_warn_without_aborting_or_pruning(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            visible = source / "visible.txt"
            visible.write_text("readable", encoding="utf-8")

            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")

            def incomplete_traversal(_root, diagnostics=None, directory_callback=None):
                if directory_callback:
                    directory_callback(source, "available", None)
                diagnostics.record_error(source / "restricted", PermissionError("permission denied"))
                yield visible

            with patch("app.curator.iter_source_files", side_effect=incomplete_traversal):
                result = curator.scan()

            self.assertEqual(result["source_read_errors"], 1)
            self.assertEqual(curator.summary()["files"], 1)
            self.assertFalse(result["removed_missing_records"])
            self.assertIn("restricted", curator.summary()["last_source_inventory"]["first_source_error"])

    def test_root_scan_assigns_configured_output_ownership(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            destination = output / "photo.jpg"
            destination.write_bytes(b"photo")
            destination.chmod(0o600)
            curator = Curator(
                source, output, quarantine, config / "catalog.sqlite3",
                output_uid=99, output_gid=100,
            )

            with patch("app.curator.os.geteuid", return_value=0), patch("app.curator.os.chown") as chown:
                curator._normalize_output_file(destination)

            chown.assert_called_once_with(destination, 99, 100)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o664)

    def test_existing_catalog_migrates_media_columns_before_indexes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            db_path = config / "catalog.sqlite3"
            with connect(db_path) as db:
                db.execute(
                    """CREATE TABLE files (
                         id INTEGER PRIMARY KEY,
                         path TEXT NOT NULL UNIQUE,
                         relative_path TEXT NOT NULL,
                         name TEXT NOT NULL,
                         extension TEXT,
                         size INTEGER NOT NULL,
                         mtime_ns INTEGER NOT NULL,
                         seen_scan TEXT,
                         mime TEXT,
                         content_hash TEXT,
                         exact_group TEXT,
                         similar_group INTEGER,
                         category TEXT,
                         category_confidence INTEGER DEFAULT 0,
                         category_reason TEXT
                       )"""
                )
                db.execute(
                    """INSERT INTO files(
                         path,relative_path,name,extension,size,mtime_ns,mime,category
                       ) VALUES(?,?,?,?,?,?,?,?)""",
                    (str(source / "old-video.mp4"), "old-video.mp4", "old-video.mp4",
                     ".mp4", 123, 1, "video/mp4", "Other Files"),
                )
                db.commit()

            Curator(source, output, quarantine, db_path)

            with connect(db_path) as db:
                columns = {row[1] for row in db.execute("PRAGMA table_info(files)")}
                indexes = {row[1] for row in db.execute("PRAGMA index_list(files)")}
                migrated = db.execute(
                    "SELECT media_kind,media_origin,category FROM files WHERE name='old-video.mp4'"
                ).fetchone()
            self.assertIn("media_kind", columns)
            self.assertIn("media_origin", columns)
            self.assertIn("idx_files_relative_path", indexes)
            self.assertIn("idx_files_media_kind", indexes)
            self.assertIn("idx_files_media_origin", indexes)
            self.assertTrue({
                "curation_label", "media_origin_source", "sensitivity_source",
                "sanitized_path", "sanitized_method", "sanitization_detail",
                "exif_latitude", "exif_longitude", "exif_lens_model", "exif_software",
                "exif_offset_time", "image_analysis_version",
            } <= columns)
            self.assertEqual(tuple(migrated), ("video", "unknown", "Videos"))

    def test_existing_reconstruction_tables_migrate_before_new_indexes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            db_path = config / "catalog.sqlite3"
            with connect(db_path) as db:
                db.execute(
                    """CREATE TABLE reconstruction_proposals(
                         file_id INTEGER PRIMARY KEY,proposed_path TEXT NOT NULL,
                         confidence INTEGER NOT NULL DEFAULT 0,basis TEXT NOT NULL,
                         reason TEXT,status TEXT NOT NULL DEFAULT 'proposed',updated_at TEXT NOT NULL
                       )"""
                )
                db.execute(
                    """CREATE TABLE recovery_context(
                         id INTEGER PRIMARY KEY,context_type TEXT NOT NULL,label TEXT NOT NULL,
                         details TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL
                       )"""
                )
                db.execute(
                    """CREATE TABLE ai_structure_suggestions(
                         id INTEGER PRIMARY KEY,suggestion_type TEXT NOT NULL,
                         source TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
                         confidence INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,
                         updated_at TEXT NOT NULL
                       )"""
                )
                db.execute(
                    """CREATE TABLE curation_chat_proposals(
                         id INTEGER PRIMARY KEY,message_id INTEGER NOT NULL,match_text TEXT NOT NULL,
                         facet_type TEXT NOT NULL,value TEXT NOT NULL,confidence INTEGER NOT NULL DEFAULT 0,
                         reason TEXT,affected_files INTEGER NOT NULL DEFAULT 0,
                         status TEXT NOT NULL DEFAULT 'pending',created_at TEXT NOT NULL,updated_at TEXT NOT NULL
                       )"""
                )
                db.commit()

            Curator(source, output, quarantine, db_path)
            with connect(db_path) as db:
                proposal_columns = {row[1] for row in db.execute("PRAGMA table_info(reconstruction_proposals)")}
                context_columns = {row[1] for row in db.execute("PRAGMA table_info(recovery_context)")}
                suggestion_columns = {
                    row[1] for row in db.execute("PRAGMA table_info(ai_structure_suggestions)")
                }
                curation_columns = {
                    row[1] for row in db.execute("PRAGMA table_info(curation_chat_proposals)")
                }
                indexes = {row[1] for row in db.execute("PRAGMA index_list(reconstruction_proposals)")}
                packet_table = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ai_packet_imports'"
                ).fetchone()
                effects_table = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='curation_rule_effects'"
                ).fetchone()
            self.assertTrue({"review_state", "user_path", "review_note", "reviewed_at"} <= proposal_columns)
            self.assertTrue({"match_text", "destination"} <= context_columns)
            self.assertTrue({"validation_state", "dossier_id", "packet_id"} <= suggestion_columns)
            self.assertTrue({
                "title", "selector_json", "actions_json", "examples_json", "validation_note",
            } <= curation_columns)
            self.assertIsNotNone(packet_table)
            self.assertIsNotNone(effects_table)
            self.assertIn("idx_reconstruction_review", indexes)

    def test_video_metadata_and_discovered_folder_reconstruction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            trip = source / "Aruba 2012"
            trip.mkdir()
            (source / "Old Engineering Projects").mkdir()
            video = trip / "VID_20120504_120000.mp4"
            video.write_bytes(b"fake-video-container")
            (source / "zero-video.mp4").touch()
            ffprobe_payload = {
                "streams": [
                    {"codec_type": "video", "codec_name": "h264", "width": 1920, "height": 1080,
                     "avg_frame_rate": "30000/1001", "tags": {"creation_time": "2012-05-04T12:00:00Z"}},
                    {"codec_type": "audio", "codec_name": "aac"},
                ],
                "format": {"duration": "12.5"},
            }
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            with patch(
                "app.curator.subprocess.run",
                return_value=Mock(returncode=0, stdout=json.dumps(ffprobe_payload), stderr=""),
            ):
                curator.scan()

            videos = curator.list_files(media_kind="video")
            self.assertEqual(len(videos), 2)
            analyzed = next(item for item in videos if item["size"] > 0)
            self.assertEqual(analyzed["category"], "Videos")
            self.assertEqual(analyzed["video_codec"], "h264")
            self.assertAlmostEqual(analyzed["video_duration"], 12.5)

            result = curator.build_reconstruction_foundation()
            self.assertEqual(result["videos"], 2)
            aruba = curator.list_folder_context("Aruba")
            self.assertEqual(len(aruba), 1)
            self.assertEqual(aruba[0]["descendant_files"], 1)
            empty = curator.list_folder_context("Old Engineering")
            self.assertEqual(len(empty), 1)
            self.assertEqual(empty[0]["descendant_files"], 0)

            curator.review_folder_context(aruba[0]["directory_id"], "recognized", "Aruba vacation")
            curator.build_reconstruction_foundation()
            proposal = next(item for item in curator.list_reconstruction_proposals() if item["file_id"] == analyzed["id"])
            self.assertIn("Recovered Structure", proposal["proposed_path"])
            self.assertIn("Aruba vacation", proposal["proposed_path"])

    def test_zero_byte_relationships_use_indexed_batches(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            live = source / "live"
            placeholders = source / "placeholders"
            live.mkdir()
            placeholders.mkdir()
            for index in range(17):
                name = f"recovered-{index}.dat"
                (live / name).write_bytes(f"content-{index}".encode())
                (placeholders / name.upper()).touch()

            curator = Curator(
                source, output, quarantine, config / "catalog.sqlite3", batch_size=8,
            )
            curator.scan()
            curator.build_reconstruction_foundation()

            with connect(config / "catalog.sqlite3") as db:
                relationship_count = db.execute(
                    "SELECT COUNT(*) FROM file_relationships WHERE relationship='zero_same_name'"
                ).fetchone()[0]
                indexes = {row[1] for row in db.execute("PRAGMA index_list(files)")}
            self.assertEqual(relationship_count, 17)
            self.assertIn("idx_files_name_nocase_size", indexes)

    def test_recovery_context_and_ai_provider_settings_are_scan_local(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.add_recovery_context("device", "Galaxy phone", "Used for personal photos")
            self.assertEqual(curator.list_recovery_context()[0]["label"], "Galaxy phone")
            settings = curator.save_ai_provider_settings({
                "provider_name": "Local vision", "endpoint": "http://ollama:11434", "model": "vision-model",
                "enabled": True, "allow_cloud_media": False, "allow_sensitive_media": False,
            })
            self.assertTrue(settings["enabled"])
            self.assertTrue(settings["is_local"])
            self.assertFalse(settings["allow_cloud_media"])
            with connect(config / "catalog.sqlite3") as db:
                question_id = db.execute(
                    """INSERT INTO review_questions(source,question,status,created_at,updated_at)
                       VALUES('test','Do you recognize this folder?','open','now','now')"""
                ).lastrowid
                db.commit()
            curator.answer_review_question(question_id, "It came from my old laptop.")
            self.assertEqual(curator.list_review_questions(), [])
            self.assertEqual(len(curator.list_recovery_context()), 2)

    def test_ai_api_key_is_saved_outside_database_and_can_be_replaced_or_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            values = {
                "provider_id": "openai", "provider_name": "OpenAI",
                "endpoint": "https://api.openai.com/v1", "model": "vision-model",
                "api_key": "sk-test-secret", "enabled": True,
                "allow_cloud_media": True, "allow_sensitive_media": False,
            }
            settings = curator.save_ai_provider_settings(values)
            self.assertTrue(settings["has_api_key"])
            self.assertNotIn("api_key", settings)
            secret_path = config / "ai-provider-secret.json"
            self.assertEqual(stat.S_IMODE(secret_path.stat().st_mode), 0o600)
            with connect(config / "catalog.sqlite3") as db:
                stored = json.dumps(dict(db.execute("SELECT * FROM ai_provider_settings").fetchone()))
            self.assertNotIn("sk-test-secret", stored)

            with patch.object(AIProviderClient, "test_connection", autospec=True) as connection:
                connection.return_value = {"ok": True, "local": False, "models": ["vision-model"]}
                curator.test_ai_provider()
                self.assertEqual(connection.call_args.args[0].config.api_key, "sk-test-secret")

            values["api_key"] = ""
            curator.save_ai_provider_settings(values)
            self.assertTrue(curator.ai_provider_settings()["has_api_key"])
            values["clear_api_key"] = True
            curator.save_ai_provider_settings(values)
            self.assertFalse(curator.ai_provider_settings()["has_api_key"])
            self.assertFalse(secret_path.exists())

    def test_ai_provider_endpoint_normalization_supports_cloud_and_local_presets(self):
        gemini = AIProviderClient(ProviderConfig(endpoint="https://generativelanguage.googleapis.com/v1beta/openai"))
        ollama = AIProviderClient(ProviderConfig(endpoint="http://ollama:11434"))
        self.assertEqual(gemini._base_v1(), "https://generativelanguage.googleapis.com/v1beta/openai")
        self.assertEqual(ollama._base_v1(), "http://ollama:11434/v1")
        with self.assertRaisesRegex(ValueError, "Paste the actual secret"):
            ProviderConfig(api_key_env="sk-actual-key").validate()

    def test_anthropic_uses_native_headers_messages_and_vision_payload(self):
        config = ProviderConfig(
            provider_id="anthropic", provider_name="Anthropic Claude",
            endpoint="https://api.anthropic.com/v1", model="claude-vision-test",
            api_key="sk-ant-test", enabled=True, allow_cloud_media=True,
        )
        client = AIProviderClient(config)
        model_response = MagicMock()
        model_response.__enter__.return_value = model_response
        model_response.read.return_value = json.dumps({
            "data": [{"id": "claude-vision-test"}, {"id": "claude-other"}],
        }).encode()
        with patch("app.ai.urllib.request.urlopen", return_value=model_response) as opener:
            result = client.test_connection()
        request = opener.call_args.args[0]
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(request.full_url, "https://api.anthropic.com/v1/models")
        self.assertEqual(headers["x-api-key"], "sk-ant-test")
        self.assertEqual(headers["anthropic-version"], "2023-06-01")
        self.assertNotIn("authorization", headers)
        self.assertIn("claude-vision-test", result["models"])

        with tempfile.TemporaryDirectory() as temp:
            preview = Path(temp) / "preview.jpg"
            preview.write_bytes(b"reduced-preview")
            expected = {
                "caption": "Recovered photo", "origin": "camera", "sensitivity": "normal",
                "topics": [], "people_labels": [], "confidence": 90, "reason": "visual evidence",
                "questions": [],
            }
            message_response = MagicMock()
            message_response.__enter__.return_value = message_response
            message_response.read.return_value = json.dumps({
                "content": [{"type": "text", "text": json.dumps(expected)}],
            }).encode()
            with patch("app.ai.urllib.request.urlopen", return_value=message_response) as opener:
                analyzed = client.analyze_media(preview, {"sensitivity": "normal"}, [])
            request = opener.call_args.args[0]
            payload = json.loads(request.data.decode())
            self.assertEqual(request.full_url, "https://api.anthropic.com/v1/messages")
            self.assertNotIn("temperature", payload)
            self.assertEqual(payload["output_config"]["format"]["type"], "json_schema")
            self.assertEqual(payload["output_config"]["format"]["schema"]["type"], "object")
            self.assertEqual(payload["system"].split()[0], "You")
            image = payload["messages"][0]["content"][0]
            self.assertEqual(image["type"], "image")
            self.assertEqual(image["source"]["type"], "base64")
            self.assertEqual(image["source"]["media_type"], "image/jpeg")
            self.assertEqual(analyzed, expected)

        structure = {"decisions": []}
        structure_response = MagicMock()
        structure_response.__enter__.return_value = structure_response
        structure_response.read.return_value = json.dumps({
            "content": [{"type": "text", "text": json.dumps(structure)}],
        }).encode()
        with patch("app.ai.urllib.request.urlopen", return_value=structure_response) as opener:
            self.assertEqual(client.analyze_structure([{"relative_path": "Recovered"}], []), structure)
        structure_payload = json.loads(opener.call_args.args[0].data.decode())
        self.assertEqual(structure_payload["max_tokens"], 2048)
        self.assertIn("exactly one decision", structure_payload["system"])
        schema = structure_payload["output_config"]["format"]["schema"]
        encoded_schema = json.dumps(schema)
        self.assertNotIn('"maxItems"', encoded_schema)
        self.assertNotIn('"maxLength"', encoded_schema)
        supported_keywords = {"type", "properties", "required", "additionalProperties", "items", "enum"}

        def assert_anthropic_schema_subset(node):
            self.assertTrue(set(node).issubset(supported_keywords), set(node) - supported_keywords)
            for child in node.get("properties", {}).values():
                assert_anthropic_schema_subset(child)
            if isinstance(node.get("items"), dict):
                assert_anthropic_schema_subset(node["items"])

        assert_anthropic_schema_subset(schema)

    def test_ai_json_parser_accepts_fenced_and_explained_objects(self):
        expected = {"folder_suggestions": [], "path_rules": [], "summary": "No safe inference"}
        fenced = "Here is the analysis:\n```json\n" + json.dumps(expected) + "\n```\nDone."
        self.assertEqual(
            AIProviderClient._json_object(fenced, "invalid response"), expected,
        )
        with_braces_in_text = (
            "I considered {folder names}, then returned "
            + json.dumps({"summary": "A {literal} value", "folder_suggestions": [], "path_rules": []})
            + " after the explanation."
        )
        self.assertEqual(
            AIProviderClient._json_object(with_braces_in_text, "invalid response")["summary"],
            "A {literal} value",
        )

    def test_ai_json_parser_preserves_unusable_provider_reply(self):
        reply = "I could not produce the requested object because the input was ambiguous."
        with self.assertRaises(AIProviderResponseError) as raised:
            AIProviderClient._json_object(reply, "invalid response")
        self.assertEqual(raised.exception.raw_response, reply)
        self.assertIn("Provider reply began", str(raised.exception))

    def test_curation_conversation_accepts_complete_json_with_max_tokens_stop(self):
        client = AIProviderClient(ProviderConfig(
            provider_id="anthropic", provider_name="Claude",
            endpoint="https://api.anthropic.com/v1", model="claude-test",
            enabled=True, allow_cloud_media=True,
        ))
        expected = {"reply": "One short answer.", "searches": [], "proposals": []}
        response = {
            "stop_reason": "max_tokens",
            "content": [{"type": "text", "text": json.dumps(expected)}],
        }
        with patch.object(client, "_message", return_value=response) as message:
            result = client.curation_conversation([], {"summary": {}})
        self.assertEqual(result, expected)
        self.assertEqual(message.call_count, 1)

    def test_curation_conversation_compactly_retries_truncated_response(self):
        client = AIProviderClient(ProviderConfig(
            provider_id="anthropic", provider_name="Claude",
            endpoint="https://api.anthropic.com/v1", model="claude-test",
            enabled=True, allow_cloud_media=True,
        ))
        expected = {"reply": "Here is the concise answer.", "searches": [], "proposals": []}
        responses = [
            {
                "stop_reason": "max_tokens",
                "content": [{"type": "text", "text": '{"reply":"unfinished'}],
            },
            {
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": json.dumps(expected)}],
            },
        ]
        context = {
            "summary": {"files": 100},
            "representative_samples": [{"name": f"sample-{index}"} for index in range(40)],
        }
        with patch.object(client, "_message", side_effect=responses) as message:
            result = client.curation_conversation(
                [{"role": "user", "content": "Answer one question."}], context,
            )
        self.assertEqual(result, expected)
        self.assertEqual(message.call_count, 2)
        self.assertEqual(message.call_args_list[0].kwargs["max_tokens"], 4096)
        self.assertEqual(message.call_args_list[1].kwargs["max_tokens"], 8192)
        retry_prompt = message.call_args_list[1].args[1]
        self.assertIn("previous response was cut off", retry_prompt)
        self.assertIn("sample-11", retry_prompt)
        self.assertNotIn("sample-12", retry_prompt)

    def test_anthropic_endpoint_is_recognized_for_existing_custom_settings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            settings = curator.save_ai_provider_settings({
                "provider_id": "custom", "provider_name": "Claude",
                "endpoint": "https://api.anthropic.com/v1", "model": "claude-test",
                "enabled": True, "allow_cloud_media": True,
            })
            self.assertEqual(settings["provider_id"], "anthropic")

    def test_folder_feedback_context_rules_and_facets_change_reconstruction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            noise = source / "Recovered Files"
            private = source / "Private Shots"
            system = source / "System Cache"
            original = source / "Original Structure"
            organized = original / "Organized By Me"
            vacation = organized / "Vacation"
            empty_original = original / "Empty Original Album"
            for directory in (noise, private, system, vacation, empty_original):
                directory.mkdir(parents=True)
            Image.new("RGB", (32, 32), (20, 40, 60)).save(noise / "snapsave-trip.png")
            Image.new("RGB", (32, 32), (80, 20, 40)).save(private / "private.png")
            (system / "cache.bin").write_bytes(b"application cache")
            Image.new("RGB", (32, 32), (10, 10, 10)).save(source / "space.png")
            Image.new("RGB", (32, 32), (15, 25, 35)).save(vacation / "nested.png")
            uncertain = source / "Uncertain Dump" / "Mystery"
            uncertain.mkdir(parents=True)
            Image.new("RGB", (32, 32), (5, 15, 25)).save(uncertain / "unplaced.png")

            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.scan()
            curator.build_reconstruction_foundation()
            noise_folder = curator.list_folder_context("Recovered Files")[0]
            private_folder = curator.list_folder_context("Private Shots")[0]
            system_folder = curator.list_folder_context("System Cache")[0]
            original_folder = curator.list_folder_context("Original Structure")[0]
            organized_folder = curator.list_folder_context("Organized By Me")[0]
            curator.review_folder_context(noise_folder["directory_id"], "noise")
            curator.review_folder_context(private_folder["directory_id"], "private", "Personal")
            curator.review_folder_context(system_folder["directory_id"], "system")
            curator.review_folder_context(original_folder["directory_id"], "recognized", "Recovered Originals")
            curator.review_folder_context(organized_folder["directory_id"], "noise", notes="Folder I created while sorting")
            curator.add_recovery_context(
                "application", "SnapSave exports", "Saved Snapchat media",
                "snapsave", "Media/Photos/Snapchat",
            )
            space = next(item for item in curator.list_files() if item["name"] == "space.png")
            curator.set_file_facet(space["id"], "topic", "NASA")
            with connect(config / "catalog.sqlite3") as db:
                curator._build_reconstruction_proposals(db)
                db.commit()

            proposals = {item["name"]: item for item in curator.list_reconstruction_proposals(limit=100)}
            self.assertTrue(proposals["snapsave-trip.png"]["effective_path"].startswith("Media/Photos/Snapchat/"))
            self.assertTrue(proposals["private.png"]["effective_path"].startswith("Private/Recovered Structure/Personal/"))
            self.assertEqual(proposals["cache.bin"]["status"], "excluded_system")
            self.assertIn("NASA", proposals["space.png"]["effective_path"])
            self.assertEqual(proposals["space.png"]["basis"], "interpreted_category")
            self.assertIn("Recovered Originals/Vacation/nested.png", proposals["nested.png"]["effective_path"])
            self.assertNotIn("Organized By Me", proposals["nested.png"]["effective_path"])
            self.assertTrue(proposals["unplaced.png"]["effective_path"].startswith("Organized Library/"))
            self.assertNotIn("Uncertain Dump", proposals["unplaced.png"]["effective_path"])
            self.assertNotIn("Mystery", proposals["unplaced.png"]["effective_path"])
            self.assertEqual(proposals["unplaced.png"]["basis"], "sanitized_category")
            with connect(config / "catalog.sqlite3") as db:
                directory_paths = {
                    row[0] for row in db.execute(
                        "SELECT proposed_path FROM reconstruction_directories WHERE status='included'"
                    )
                }
            self.assertIn(
                "Recovered Structure/Recovered Originals/Empty Original Album", directory_paths,
            )
            self.assertIn("Recovered Structure/Recovered Originals/Vacation", directory_paths)
            self.assertFalse(any("Organized By Me" in path for path in directory_paths))

    def test_complete_ai_dossier_contains_context_empty_folders_files_and_plan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            originals = source / "Original Structure"
            (originals / "Empty Album").mkdir(parents=True)
            (originals / "snapchat-memory.jpg").write_bytes(b"recovered media")
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.scan()
            curator.build_reconstruction_foundation()
            folder = curator.list_folder_context("Original Structure")[0]
            curator.review_folder_context(
                folder["directory_id"], "recognized", "Recovered Originals",
                "This branch contains the original empty folder tree.",
            )
            curator.add_recovery_context(
                "application", "Snapchat saves", "Saved by the Snapchat application.",
                "snapchat", "Media/Photos/Snapchat",
            )
            with connect(config / "catalog.sqlite3") as db:
                curator._build_reconstruction_proposals(db)
                db.commit()

            result = curator.export_ai_reconstruction_dossier()
            dossier = Path(result["path"])
            text = dossier.read_text(encoding="utf-8")
            self.assertEqual(dossier.name, "reconstruction_ai_dossier.txt")
            self.assertIn("REQUIRED OUTPUT", text)
            self.assertIn('"action":"no_change|folder_status|path_rule|ask_user"', text)
            self.assertIn('"label":"Snapchat saves"', text)
            self.assertIn('"relative_path":"Original Structure/Empty Album"', text)
            self.assertIn('"relative_path":"Original Structure/snapchat-memory.jpg"', text)
            self.assertIn('"current_destination":"Recovered Structure/Recovered Originals/Empty Album"', text)
            self.assertEqual(result["files"], 1)
            self.assertGreaterEqual(result["directories"], 3)
            self.assertGreater(result["bytes"], 0)

    def test_ai_work_packets_are_branch_aware_importable_and_apply_only_after_complete_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            for branch in ("Camera Roll", "Recovered Downloads"):
                folder = source / branch
                folder.mkdir()
                (folder / ("IMG_20200101_120000.jpg" if branch == "Camera Roll" else "wallpaper-space.jpg")).write_bytes(b"evidence")
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.scan()
            curator.build_reconstruction_foundation()
            folder_rows = {
                item["relative_path"]: item for item in curator.list_folder_context(limit=100)
            }
            original_builder = curator._ai_branch_evidence

            def oversized_branch(db, branch):
                units = original_builder(db, branch)
                self.assertEqual(len(units), 1)
                units[0]["representative_files"].append({"name": "x" * 50000})
                return units

            with patch.object(curator, "_ai_branch_evidence", side_effect=oversized_branch):
                package = curator.generate_ai_work_package(target_tokens=10000)
            self.assertEqual(package["packet_count"], 2)
            self.assertEqual(package["imported_count"], 0)
            first_packet = json.loads(
                curator.ai_work_packet_path("packet-001").read_text(encoding="utf-8")
            )
            self.assertEqual(first_packet["schema_version"], 1)
            self.assertEqual(first_packet["dossier_id"], package["dossier_id"])
            self.assertIn("required_output", first_packet)
            first_path = first_packet["evidence_units"][0]["folders"][0]["relative_path"]
            response_one = {
                "schema_version": 1, "dossier_id": package["dossier_id"],
                "packet_id": "packet-001", "coverage_complete": True,
                "decisions": [{
                    "focal_path": first_path, "action": "folder_status",
                    "review_status": "recognized", "user_label": "Original Camera Media",
                    "match_text": "", "destination": "", "confidence": 94,
                    "reason": "The branch name and camera filename pattern support preserving it.",
                    "question": "",
                }],
            }
            imported_one = curator.import_ai_work_packet_response(json.dumps(response_one))
            self.assertEqual(imported_one["valid"], 1)
            self.assertEqual(imported_one["package"]["imported_count"], 1)
            suggestion = curator.list_structure_suggestions()[0]
            with self.assertRaisesRegex(RuntimeError, "Import every packet"):
                curator.review_structure_suggestions_batch([suggestion["id"]], "accepted")

            response_two = {
                "schema_version": 1, "dossier_id": package["dossier_id"],
                "packet_id": "packet-002", "coverage_complete": True, "decisions": [],
            }
            imported_two = curator.import_ai_work_packet_response(json.dumps(response_two))
            self.assertTrue(imported_two["package"]["complete"])
            applied = curator.review_structure_suggestions_batch([suggestion["id"]], "accepted")
            self.assertEqual(applied, {"reviewed": 1, "accepted": 1})
            updated = curator.list_folder_context(first_path)[0]
            self.assertEqual(updated["review_status"], "recognized")
            self.assertEqual(updated["user_label"], "Original Camera Media")
            self.assertFalse(curator.ai_work_package_status()["current"])
            self.assertIn(first_path, folder_rows)

    def test_ai_work_packet_import_rejects_stale_or_incomplete_responses(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            branch = source / "Recovered"
            branch.mkdir()
            (branch / "snapsave-image.jpg").write_bytes(b"evidence")
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.scan()
            curator.build_reconstruction_foundation()
            package = curator.generate_ai_work_package()
            response = {
                "schema_version": 1, "dossier_id": package["dossier_id"],
                "packet_id": "packet-001", "coverage_complete": False, "decisions": [],
            }
            with self.assertRaisesRegex(ValueError, "complete packet"):
                curator.import_ai_work_packet_response(json.dumps(response))
            response["coverage_complete"] = True
            response["decisions"] = [{
                "focal_path": "Recovered", "action": "path_rule", "review_status": "",
                "user_label": "Invented", "match_text": "not-visible-in-this-packet",
                "destination": "Media/Invented", "confidence": 99, "reason": "Unsupported",
                "question": "",
            }]
            imported = curator.import_ai_work_packet_response(json.dumps(response))
            self.assertEqual(imported["ignored"], 1)
            self.assertEqual(curator.list_structure_suggestions(), [])
            curator.add_recovery_context("application", "SnapSave", "Recovered Snapchat saves")
            with self.assertRaisesRegex(RuntimeError, "stale"):
                curator.import_ai_work_packet_response(json.dumps(response))

    def test_ai_work_packet_bulk_import_reports_each_response_and_continues_after_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            (source / "Camera Roll").mkdir()
            (source / "Camera Roll" / "IMG_20200101_120000.jpg").write_bytes(b"evidence")
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.scan()
            curator.build_reconstruction_foundation()
            package = curator.generate_ai_work_package()
            response = json.dumps({
                "schema_version": 1, "dossier_id": package["dossier_id"],
                "packet_id": "packet-001", "coverage_complete": True, "decisions": [],
            })

            result = curator.import_ai_work_packet_responses([
                ("response-001.json", response),
                ("duplicate-001.json", response),
                ("broken.json", "not json"),
            ])

            self.assertEqual(result["total"], 3)
            self.assertEqual(result["imported"], 1)
            self.assertEqual(result["failed"], 2)
            self.assertEqual([item["status"] for item in result["results"]], [
                "imported", "error", "error",
            ])
            self.assertIn("supplied more than once", result["results"][1]["error"])
            self.assertIn("usable JSON", result["results"][2]["error"])
            self.assertTrue(result["package"]["complete"])
            with connect(config / "catalog.sqlite3") as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM ai_packet_imports").fetchone()[0], 1)

    def test_conversational_curation_stages_and_applies_broad_label_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            snaps = source / "SnapSave Export"
            snaps.mkdir()
            (snaps / "one.jpg").write_bytes(b"first recovered snap")
            (snaps / "two.mp4").write_bytes(b"second recovered snap")
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.scan()
            curator.save_ai_provider_settings({
                "provider_id": "ollama", "provider_name": "Local Assistant",
                "endpoint": "http://ai.local:11434/v1", "model": "test-model", "enabled": True,
            })
            ai_result = {
                "reply": "That path is strong evidence for a Snapchat export collection.",
                "proposals": [{
                    "match_text": "SnapSave", "facet_type": "collection",
                    "value": "Snapchat Exports", "confidence": 96,
                    "reason": "The owner confirmed the application export folder.",
                }],
            }
            with patch("app.ai.AIProviderClient.curation_conversation", return_value=ai_result):
                conversation = curator.send_curation_message(
                    "SnapSave Export is where I saved Snapchat exports."
                )
            proposal = conversation["proposals"][0]
            self.assertEqual(proposal["affected_files"], 2)
            exact_preview = curator.sanitization_preview(authorize=True)
            self.assertTrue(exact_preview["authorized"])
            applied = curator.review_curation_proposal(proposal["id"], "accepted")
            self.assertEqual(applied["affected"], 2)
            retained_overview = curator.sanitization_overview()
            self.assertFalse(retained_overview.get("stale", False))
            self.assertTrue(retained_overview["authorized"])
            self.assertEqual(retained_overview["included"], exact_preview["included"])
            with connect(config / "catalog.sqlite3") as db:
                labels = {row[0] for row in db.execute(
                    "SELECT curation_label FROM files WHERE curation_label IS NOT NULL"
                )}
            self.assertEqual(labels, {"Snapchat Exports"})

    def test_curation_agent_searches_full_catalog_applies_multiple_labels_and_undoes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            for index in range(85):
                (source / f"ordinary-{index:03d}.bin").write_bytes(f"ordinary {index}".encode())
            (source / "~valegenta_saved.jpg").write_bytes(b"instagram one")
            (source / "~taylorgallo__saved.mp4").write_bytes(b"instagram two")
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.scan()
            curator.save_ai_provider_settings({
                "provider_id": "ollama", "provider_name": "Local Assistant",
                "endpoint": "http://ai.local:11434/v1", "model": "test-model", "enabled": True,
            })
            selector = {"field": "name", "operator": "starts_with", "value": "~"}
            responses = [
                {
                    "reply": "I will check every tilde-prefixed filename.",
                    "searches": [{"label": "Tilde handles", "selector": selector}],
                    "proposals": [],
                },
                {
                    "reply": "The complete catalog search supports one reusable rule.",
                    "searches": [],
                    "proposals": [{
                        "title": "Instagram saved media", "selector": selector,
                        "actions": {"collection": "Instagram Saved", "sensitivity": "adult"},
                        "confidence": 98, "reason": "The owner identified the tilde naming convention.",
                    }],
                },
            ]
            with patch(
                "app.ai.AIProviderClient.curation_conversation", side_effect=responses,
            ) as converse:
                conversation = curator.send_curation_message(
                    "All tilde-pattern handles are adult Instagram saves."
                )
            self.assertEqual(converse.call_count, 2)
            second_search_results = converse.call_args_list[1].args[2]
            self.assertEqual(second_search_results[0]["matches"], 2)
            self.assertEqual(conversation["turn"], {
                "searches_run": 1, "staged": 1, "invalid": 0, "reply_kind": "suggestions",
            })
            proposal = next(item for item in conversation["proposals"] if item["status"] == "pending")
            self.assertEqual(proposal["affected_files"], 2)
            self.assertEqual(proposal["actions"], {
                "collection": "Instagram Saved", "sensitivity": "adult",
            })
            applied = curator.review_curation_proposal(proposal["id"], "accepted")
            self.assertEqual(applied["affected"], 2)
            with connect(config / "catalog.sqlite3") as db:
                labeled = db.execute(
                    """SELECT COUNT(*) FROM files WHERE name LIKE '~%'
                       AND curation_label='Instagram Saved' AND sensitivity='adult'"""
                ).fetchone()[0]
            self.assertEqual(labeled, 2)
            later_response = {
                "reply": "A more restrictive sensitivity suggestion is ready.", "searches": [],
                "proposals": [{
                    "title": "Tilde media privacy", "selector": selector,
                    "actions": {"sensitivity": "intimate"}, "confidence": 90,
                    "reason": "A later privacy rule for the same files.",
                }],
            }
            with patch(
                "app.ai.AIProviderClient.curation_conversation", return_value=later_response,
            ):
                later_conversation = curator.send_curation_message("Treat those as intimate instead.")
            later = next(
                item for item in later_conversation["proposals"] if item["status"] == "pending"
            )
            curator.review_curation_proposal(later["id"], "accepted")
            with self.assertRaisesRegex(ValueError, "newer applied AI rule"):
                curator.review_curation_proposal(proposal["id"], "undone")
            curator.review_curation_proposal(later["id"], "undone")
            undone = curator.review_curation_proposal(proposal["id"], "undone")
            self.assertEqual(undone["affected"], 2)
            with connect(config / "catalog.sqlite3") as db:
                restored = db.execute(
                    """SELECT COUNT(*) FROM files WHERE name LIKE '~%'
                       AND curation_label IS NULL AND sensitivity='unknown'"""
                ).fetchone()[0]
            self.assertEqual(restored, 2)

    def test_curation_agent_exposes_question_only_and_invalid_suggestion_states(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            (source / "camera-photo.jpg").write_bytes(b"photo")
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.scan()
            curator.save_ai_provider_settings({
                "provider_id": "ollama", "provider_name": "Local Assistant",
                "endpoint": "http://ai.local:11434/v1", "model": "test-model", "enabled": True,
            })
            question = {"reply": "Were these taken by you?", "searches": [], "proposals": []}
            with patch("app.ai.AIProviderClient.curation_conversation", return_value=question):
                conversation = curator.send_curation_message("Help identify these files.")
            self.assertEqual(conversation["turn"]["reply_kind"], "conversation")
            self.assertEqual(conversation["turn"]["staged"], 0)

            invalid = {
                "reply": "I could not verify that proposed pattern.", "searches": [],
                "proposals": [{
                    "title": "Missing Snapchat export", "selector": {
                        "field": "name", "operator": "contains", "value": "SnapSave",
                    },
                    "actions": {"collection": "Snapchat Saved"},
                    "confidence": 80, "reason": "Unverified naming clue.",
                }],
            }
            with patch("app.ai.AIProviderClient.curation_conversation", return_value=invalid):
                conversation = curator.send_curation_message("What about SnapSave?")
            self.assertEqual(conversation["turn"]["invalid"], 1)
            rejected = next(item for item in conversation["proposals"] if item["status"] == "invalid")
            self.assertIn("zero eligible", rejected["validation_note"])

    def test_reconstruction_review_dry_run_and_export_are_safety_gated(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            recovered = source / "report.txt"
            recovered.write_text("important recovered document", encoding="utf-8")
            empty = source / "Original Empty Tree" / "Empty Child"
            empty.mkdir(parents=True)
            curator = Curator(
                source, output, quarantine, config / "catalog.sqlite3", allow_actions=True,
            )
            curator.scan()
            curator.build_reconstruction_foundation()
            original_folder = curator.list_folder_context("Original Empty Tree")[0]
            curator.review_folder_context(original_folder["directory_id"], "recognized", "Original Tree")
            with connect(config / "catalog.sqlite3") as db:
                curator._build_reconstruction_proposals(db)
                db.commit()
            proposal = curator.list_reconstruction_proposals()[0]
            curator.review_reconstruction_proposal(
                proposal["file_id"], "accepted", "Recovered Documents/report.txt", "verified",
            )

            unauthorized = curator.reconstruction_export_preview()
            self.assertFalse(unauthorized["authorized"])
            authorized = curator.reconstruction_export_preview(authorize=True)
            self.assertTrue(authorized["authorized"])
            self.assertEqual(authorized["ready"], 1)
            result = curator.export_reconstruction(authorized["token"])
            self.assertEqual(result["exported"], 1)
            self.assertEqual((output / "Recovered Documents" / "report.txt").read_text(), recovered.read_text())
            self.assertTrue((output / "Recovered Structure" / "Original Tree" / "Empty Child").is_dir())
            self.assertFalse(curator.reconstruction_export_preview()["authorized"])

    def test_ai_batch_candidates_use_one_exact_duplicate_representative(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            sample = source / "one.png"
            Image.new("RGB", (32, 32), (50, 70, 90)).save(sample)
            (source / "two.png").write_bytes(sample.read_bytes())
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.scan()
            candidates = curator._ai_batch_candidates(limit=100)
            self.assertEqual(len(candidates), 1)
            curator.save_ai_provider_settings({
                "provider_name": "Local vision", "endpoint": "http://ollama:11434",
                "model": "vision", "enabled": True, "allow_cloud_media": False,
                "allow_sensitive_media": False,
            })
            ai_result = {
                "caption": "A space image", "origin": "downloaded", "sensitivity": "normal",
                "topics": ["NASA"], "people_labels": [], "confidence": 91,
                "reason": "visual evidence", "questions": [],
            }
            with patch("app.ai.AIProviderClient.analyze_media", return_value=ai_result):
                curator.analyze_file_with_ai(candidates[0])
            with connect(config / "catalog.sqlite3") as db:
                analyzed = db.execute(
                    "SELECT COUNT(*) FROM files WHERE ai_updated_at IS NOT NULL AND media_origin='downloaded'"
                ).fetchone()[0]
                topic_facets = db.execute(
                    "SELECT COUNT(*) FROM file_facets WHERE facet_type='topic' AND value='NASA'"
                ).fetchone()[0]
            self.assertEqual(analyzed, 2)
            self.assertEqual(topic_facets, 2)

    def test_ai_interprets_folder_context_as_reviewable_suggestions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            organized = source / "Sorted Recovery"
            organized.mkdir()
            original = organized / "Original Albums"
            original.mkdir()
            (original / "family-reunion-2012.jpg").write_text("recovered", encoding="utf-8")
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.scan()
            curator.build_reconstruction_foundation()
            folder = curator.list_folder_context("Sorted Recovery")[0]
            curator.review_folder_context(
                folder["directory_id"], "recognized", notes="I made this folder while sorting recovery output",
            )
            curator.add_recovery_context(
                "general", "Sorting history", "Folders I made during recovery should not be preserved.",
            )
            curator.save_ai_provider_settings({
                "provider_name": "Local vision", "endpoint": "http://ollama:11434",
                "model": "vision", "enabled": True, "allow_cloud_media": False,
                "allow_sensitive_media": False,
            })
            response = {
                "decisions": [{
                    "focal_path": "Sorted Recovery", "action": "folder_status",
                    "review_status": "noise", "user_label": "", "match_text": "",
                    "destination": "", "confidence": 96,
                    "reason": "User says this was a temporary sorting folder", "question": "",
                }],
            }
            with patch("app.ai.AIProviderClient.analyze_structure", return_value=response) as analyze:
                curator._structure_ai_wrapper(100)
            evidence, _, plan = analyze.call_args.args
            sorted_recovery = next(item for item in evidence if item["relative_path"] == "Sorted Recovery")
            self.assertEqual(sorted_recovery["current_outcome"], "preserve this surviving hierarchy under Recovered Structure")
            self.assertIn("Original Albums", [item["name"] for item in sorted_recovery["child_folders"]])
            self.assertIn(
                "family-reunion-2012.jpg",
                [item["name"] for item in sorted_recovery["representative_files"]],
            )
            self.assertIn("currently_using_safe_category_fallback", plan)
            suggestions = curator.list_structure_suggestions()
            self.assertEqual(len(suggestions), 1)
            self.assertEqual(suggestions[0]["review_status"], "noise")
            curator.review_structure_suggestion(suggestions[0]["id"], "accepted")
            updated = next(
                item for item in curator.list_folder_context("Sorted Recovery")
                if item["relative_path"] == "Sorted Recovery"
            )
            self.assertEqual(updated["review_status"], "noise")

    def test_structure_ai_discards_noops_and_zero_match_rules_but_keeps_useful_questions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            photos = source / "Recovered Photos"
            photos.mkdir()
            (photos / "IMG_20190101_120000.jpg").write_bytes(b"not-an-image")
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.scan()
            curator.build_reconstruction_foundation()
            folder = curator.list_folder_context("Recovered Photos")[0]
            curator.review_folder_context(folder["directory_id"], "recognized", "Family Photos")
            curator.save_ai_provider_settings({
                "provider_id": "ollama", "provider_name": "Local AI",
                "endpoint": "http://ollama:11434/v1", "model": "vision", "enabled": True,
            })
            response = {
                "decisions": [
                    {
                        "focal_path": "Recovered Photos", "action": "folder_status",
                        "review_status": "recognized", "user_label": "Family Photos",
                        "match_text": "", "destination": "", "confidence": 99,
                        "reason": "Already correct", "question": "",
                    },
                    {
                        "focal_path": "Recovered Photos", "action": "path_rule",
                        "review_status": "", "user_label": "Imaginary",
                        "match_text": "does-not-exist", "destination": "Media/Imaginary",
                        "confidence": 95, "reason": "No evidence", "question": "",
                    },
                    {
                        "focal_path": "Recovered Photos", "action": "ask_user",
                        "review_status": "", "user_label": "", "match_text": "",
                        "destination": "", "confidence": 80,
                        "reason": "The answer changes the origin category.",
                        "question": "Were these photos exported from a phone or copied from a camera?",
                    },
                ],
            }
            with patch("app.ai.AIProviderClient.analyze_structure", return_value=response):
                curator._structure_ai_wrapper(100)
            self.assertEqual(curator.list_structure_suggestions(), [])
            questions = curator.list_review_questions()
            self.assertEqual(len(questions), 1)
            self.assertIn("origin category", questions[0]["question"])

    def test_structure_ai_uses_bounded_passes_and_reports_progress(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            now = "2026-01-01T00:00:00+00:00"
            with connect(config / "catalog.sqlite3") as db:
                db.executemany(
                    """INSERT INTO folder_context(
                         directory_id,name,relative_path,descendant_files,descendant_bytes,
                         zero_files,suggestion_score,review_status,updated_at
                       ) VALUES(?,?,?,?,?,?,?,?,?)""",
                    [
                        (number, f"Folder {number}", f"Recovered/Folder {number}", 1, 100,
                         0, 10.0, "unreviewed", now)
                        for number in range(1, 126)
                    ],
                )
                db.commit()
            curator.save_ai_provider_settings({
                "provider_id": "ollama", "provider_name": "Local AI",
                "endpoint": "http://ollama:11434/v1", "model": "vision",
                "enabled": True, "allow_cloud_media": False,
            })
            response = {"decisions": []}
            with patch("app.ai.AIProviderClient.analyze_structure", return_value=response) as analyze:
                curator._structure_ai_wrapper(12)
            self.assertEqual(analyze.call_count, 3)
            self.assertEqual([len(call.args[0]) for call in analyze.call_args_list], [4, 4, 4])
            with connect(config / "catalog.sqlite3") as db:
                run = db.execute(
                    "SELECT response_json,status FROM ai_runs ORDER BY id DESC LIMIT 1"
                ).fetchone()
            self.assertEqual(run["status"], "complete")
            self.assertEqual(json.loads(run["response_json"])["passes"], 3)
            status = curator.status()
            self.assertEqual((status["processed"], status["total"]), (3, 3))

    def test_failed_structure_ai_keeps_provider_reply_and_live_workflow_context(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            (source / "Recovered").mkdir()
            (source / "Recovered" / "photo.jpg").write_bytes(b"not-an-image")
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            curator.scan()
            curator.build_reconstruction_foundation()
            curator.save_ai_provider_settings({
                "provider_name": "Claude", "endpoint": "https://api.anthropic.com/v1",
                "model": "claude-test", "enabled": True, "allow_cloud_media": True,
            })
            failure = AIProviderResponseError("invalid response", "Claude explanation without JSON")
            with patch("app.ai.AIProviderClient.analyze_structure", side_effect=failure):
                curator._structure_ai_wrapper(100)
            state = curator.reconstruction_workspace_state()
            failed = state["ai_runs"][0]
            self.assertEqual(failed["status"], "failed")
            self.assertIn("Claude explanation", failed["response_preview"])
            self.assertEqual(state["next_action"]["id"], "ask_ai")

    def test_structure_ai_retries_overlong_batch_one_branch_at_a_time(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, quarantine, config = (
                root / name for name in ("source", "output", "quarantine", "config")
            )
            for directory in (source, output, quarantine, config):
                directory.mkdir()
            curator = Curator(source, output, quarantine, config / "catalog.sqlite3")
            now = "2026-01-01T00:00:00+00:00"
            with connect(config / "catalog.sqlite3") as db:
                db.executemany(
                    """INSERT INTO folder_context(
                         directory_id,name,relative_path,descendant_files,descendant_bytes,
                         zero_files,suggestion_score,review_status,updated_at
                       ) VALUES(?,?,?,?,?,?,?,?,?)""",
                    [
                        (number, f"Folder {number}", f"Recovered/Folder {number}", 1, 100,
                         0, 10.0, "unreviewed", now)
                        for number in range(1, 13)
                    ],
                )
                db.commit()
            curator.save_ai_provider_settings({
                "provider_id": "anthropic", "provider_name": "Claude",
                "endpoint": "https://api.anthropic.com/v1", "model": "claude-test",
                "enabled": True, "allow_cloud_media": True,
            })
            failed_once = False

            def analyze(folders, *_):
                nonlocal failed_once
                if len(folders) > 1 and not failed_once:
                    failed_once = True
                    raise AIProviderResponseError(
                        "The provider stopped before returning a usable structure analysis (max_tokens)."
                    )
                return {"decisions": []}

            with patch("app.ai.AIProviderClient.analyze_structure", side_effect=analyze) as mocked:
                curator._structure_ai_wrapper(12)
            self.assertEqual(mocked.call_count, 7)
            self.assertEqual(curator.status()["phase"], "complete")
            with connect(config / "catalog.sqlite3") as db:
                response = json.loads(db.execute(
                    "SELECT response_json FROM ai_runs ORDER BY id DESC LIMIT 1"
                ).fetchone()[0])
            self.assertEqual(response["individual_retries"], 4)


if __name__ == "__main__":
    unittest.main()
