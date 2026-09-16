import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image

from app.curator import Curator, parse_filename_date


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

            curator = Curator(source, output, quarantine, config / "catalog.sqlite3", allow_actions=True)
            curator.scan()
            summary = curator.summary()
            self.assertEqual(summary["files"], 5)
            self.assertEqual(summary["zero_files"], 1)
            self.assertEqual(summary["corrupt_files"], 1)
            self.assertEqual(summary["exact_groups"], 1)
            self.assertGreaterEqual(summary["similar_groups"], 1)
            self.assertGreaterEqual(summary["date_proposals"], 1)
            self.assertTrue((config / "recovery_catalog.csv").exists())

            curator.auto_decide_exact()
            result = curator.build_curated_library()
            self.assertGreaterEqual(result["exported"], 1)
            self.assertGreaterEqual(result["review_skipped"], 1)
            self.assertTrue((output / "recovery_catalog.jsonl").exists())

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


if __name__ == "__main__":
    unittest.main()
