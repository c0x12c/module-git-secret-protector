import builtins
import os
import tempfile
import unittest
from unittest.mock import patch, mock_open, Mock

from git_secret_protector.core.git_attributes_parser import GitAttributesParser

_REAL_OPEN = builtins.open


class TestGitAttributesParser(unittest.TestCase):

    def setUp(self):
        self.attributes_content = """
# Sample .gitattributes data for multiple filters
*.secret filter=secretfilter
config/*.conf filter=configfilter
*.data filter=datafilter
database/*.sql filter=sqlfilter
        """

        def _scoped_open(file, *args, **kwargs):
            if str(file).endswith(".gitattributes"):
                return mock_open(read_data=self.attributes_content)(
                    file, *args, **kwargs
                )
            return _REAL_OPEN(file, *args, **kwargs)

        self.open_patch = lambda: patch("builtins.open", side_effect=_scoped_open)

    def test_parse_patterns(self):
        with self.open_patch():
            parser = GitAttributesParser()
            patterns = parser.patterns

            # Assertions to ensure all filters are parsed correctly
            self.assertIn("secretfilter", patterns)
            self.assertIn("configfilter", patterns)
            self.assertIn("datafilter", patterns)
            self.assertIn("sqlfilter", patterns)
            self.assertEqual(patterns["secretfilter"], ["*.secret"])
            self.assertEqual(patterns["configfilter"], ["config/*.conf"])
            self.assertEqual(patterns["datafilter"], ["*.data"])
            self.assertEqual(patterns["sqlfilter"], ["database/*.sql"])

    @patch(
        "glob.glob", side_effect=lambda pattern, recursive: ["/fake/repo/example.data"]
    )
    def test_get_files_for_filter(self, mock_glob):
        with self.open_patch():
            parser = GitAttributesParser()
            files = parser.get_files_for_filter("datafilter")

            # Check that the files are correctly identified for the datafilter
            self.assertEqual(files, ["/fake/repo/example.data"])
            mock_glob.assert_called_once()

    def test_get_filter_name_for_file(self):
        with self.open_patch():
            parser = GitAttributesParser()
            filter_name = parser.get_filter_name_for_file(
                "/fake/repo/config/app.conf", "/fake/repo"
            )

            # Assert that the correct filter name is returned based on pattern
            self.assertEqual(filter_name, "configfilter")

    def test_get_secret_files(self):
        with self.open_patch(), patch(
            "git_secret_protector.core.git_attributes_parser.GitAttributesParser._find_files_matching_patterns",
            return_value=["/fake/repo/config/app.conf", "/fake/repo/database/test.sql"],
        ):
            parser = GitAttributesParser()
            secret_files = parser.get_secret_files()

            # Assert that all secret files from all filters are returned
            self.assertIn("/fake/repo/config/app.conf", secret_files)
            self.assertIn("/fake/repo/database/test.sql", secret_files)


class TestGitAttributesParserBaseDirAnchoring(unittest.TestCase):
    """Globbing must be anchored to settings.base_dir, not the process cwd.

    Regression: running from a subdirectory of the repo previously scanned only
    from cwd, missing files elsewhere in the repo (status/doctor fail-open).
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base_dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

        with _REAL_OPEN(os.path.join(self.base_dir, ".gitattributes"), "w") as f:
            f.write("*.secret filter=secretfilter\n")
            f.write("config/*.conf filter=configfilter\n")

        with _REAL_OPEN(os.path.join(self.base_dir, "a.secret"), "w") as f:
            f.write("x")
        os.mkdir(os.path.join(self.base_dir, "config"))
        with _REAL_OPEN(os.path.join(self.base_dir, "config", "app.conf"), "w") as f:
            f.write("x")

        # Run from a subdirectory so an unanchored ('.') glob would miss everything.
        sub = os.path.join(self.base_dir, "sub")
        os.mkdir(sub)
        prev_cwd = os.getcwd()
        os.chdir(sub)
        self.addCleanup(os.chdir, prev_cwd)

        stub_settings = Mock()
        stub_settings.base_dir = self.base_dir
        patcher = patch(
            "git_secret_protector.core.git_attributes_parser.get_settings",
            return_value=stub_settings,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_get_secret_files_anchored_to_base_dir_from_subdir(self):
        parser = GitAttributesParser()
        found = parser.get_secret_files()

        self.assertIn(os.path.join(self.base_dir, "a.secret"), found)
        self.assertIn(os.path.join(self.base_dir, "config", "app.conf"), found)

    def test_get_files_for_filter_anchored_to_base_dir_from_subdir(self):
        parser = GitAttributesParser()
        found = parser.get_files_for_filter("secretfilter")

        self.assertEqual(found, [os.path.join(self.base_dir, "a.secret")])


if __name__ == "__main__":
    unittest.main()
