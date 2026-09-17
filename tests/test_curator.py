import os
import csv
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image

from app.curator import Curator, connect, parse_filename_date


class CuratorTests(unittest.TestCase):
    def test_filename_date_is_conservative(self):
        parsed = parse_filename_date("IMG_20230517_142233.jpg")
        self.assertEqual(parsed.value, "2023-05-17T14:22:33")
        self.assertGreaterEqual(parsed.confidence, 90)
        self.assertIsNone(parse_filename_date("vacation_03-04-21.jpg").value)
        self.assertIsNone(parse_filename_date("IMG_20230231_120000.jpg").value)

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
            self.assertEqual(summary["reference_files"], 3)
            self.assertEqual(len(summary["reference_selections"]), 2)
            matches = curator.list_files(known_good=True)
            self.assertEqual(
                {item["name"] for item in matches},
                {"recovered-photo-copy.bin", "recovered-document-copy.bin"},
            )
            self.assertTrue(all(item["known_good_path"] for item in matches))

            with connect(config / "catalog.sqlite3") as db:
                decoy = db.execute(
                    "SELECT content_hash FROM reference_files WHERE path LIKE '%no-recovery-counterpart.bin'"
                ).fetchone()
                self.assertIsNone(decoy["content_hash"])

            result = curator.build_curated_library()
            self.assertEqual(result["known_good_skipped"], 2)
            self.assertEqual(result["exported"], 1)
            self.assertTrue(any(path.name == "recovered-only.txt" for path in output.rglob("*")))

            curator.decide(matches[0]["id"], "keep")
            result = curator.build_curated_library()
            self.assertEqual(result["exported"], 1)

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


if __name__ == "__main__":
    unittest.main()
