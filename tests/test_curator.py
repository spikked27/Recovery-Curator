import os
import csv
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from PIL import Image

from app.ai import AIProviderClient, AIProviderResponseError, ProviderConfig
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
            self.assertIn("idx_files_media_kind", indexes)
            self.assertIn("idx_files_media_origin", indexes)
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
                db.commit()

            Curator(source, output, quarantine, db_path)
            with connect(db_path) as db:
                proposal_columns = {row[1] for row in db.execute("PRAGMA table_info(reconstruction_proposals)")}
                context_columns = {row[1] for row in db.execute("PRAGMA table_info(recovery_context)")}
                indexes = {row[1] for row in db.execute("PRAGMA index_list(reconstruction_proposals)")}
            self.assertTrue({"review_state", "user_path", "review_note", "reviewed_at"} <= proposal_columns)
            self.assertTrue({"match_text", "destination"} <= context_columns)
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

        structure = {"folder_suggestions": [], "path_rules": [], "summary": "No safe changes"}
        structure_response = MagicMock()
        structure_response.__enter__.return_value = structure_response
        structure_response.read.return_value = json.dumps({
            "content": [{"type": "text", "text": json.dumps(structure)}],
        }).encode()
        with patch("app.ai.urllib.request.urlopen", return_value=structure_response) as opener:
            self.assertEqual(client.analyze_structure([{"relative_path": "Recovered"}], []), structure)
        structure_payload = json.loads(opener.call_args.args[0].data.decode())
        self.assertEqual(structure_payload["max_tokens"], 6144)
        self.assertIn("12 highest-impact", structure_payload["system"])

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
            (organized / "file.txt").write_text("recovered", encoding="utf-8")
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
                "folder_suggestions": [{
                    "relative_path": "Sorted Recovery", "review_status": "noise",
                    "confidence": 96, "reason": "User says this was a temporary sorting folder",
                }],
                "path_rules": [], "summary": "Temporary sorting wrapper found",
            }
            with patch("app.ai.AIProviderClient.analyze_structure", return_value=response):
                curator._structure_ai_wrapper(100)
            suggestions = curator.list_structure_suggestions()
            self.assertEqual(len(suggestions), 1)
            self.assertEqual(suggestions[0]["review_status"], "noise")
            curator.review_structure_suggestion(suggestions[0]["id"], "accepted")
            updated = curator.list_folder_context("Sorted Recovery")[0]
            self.assertEqual(updated["review_status"], "noise")

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
            response = {"folder_suggestions": [], "path_rules": [], "summary": "No change"}
            with patch("app.ai.AIProviderClient.analyze_structure", return_value=response) as analyze:
                curator._structure_ai_wrapper(125)
            self.assertEqual(analyze.call_count, 3)
            self.assertEqual([len(call.args[0]) for call in analyze.call_args_list], [60, 60, 5])
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


if __name__ == "__main__":
    unittest.main()
