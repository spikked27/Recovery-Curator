import tempfile
import unittest
from pathlib import Path

from app.profiles import ScanProfileManager


class ScanProfileManagerTests(unittest.TestCase):
    def test_profiles_create_activate_and_keep_separate_database_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp)
            manager = ScanProfileManager(config)
            original = manager.active_profile()
            second = manager.create("Second recovery pass")

            self.assertNotEqual(original["id"], second["id"])
            self.assertNotEqual(original["db_path"], second["db_path"])
            self.assertTrue(manager.active_profile()["active"])
            self.assertEqual(manager.active_profile()["name"], "Second recovery pass")

            manager.activate(original["id"])
            self.assertEqual(manager.active_profile()["id"], original["id"])
            self.assertEqual(len(manager.list_profiles()), 2)

    def test_existing_catalog_is_adopted_as_original_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp)
            legacy = config / "catalog.sqlite3"
            legacy.write_bytes(b"existing catalog marker")
            manager = ScanProfileManager(config)
            self.assertEqual(Path(manager.active_profile()["db_path"]), legacy)


if __name__ == "__main__":
    unittest.main()
