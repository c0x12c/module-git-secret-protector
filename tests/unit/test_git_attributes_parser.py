import unittest
from unittest.mock import patch, mock_open

from git_secret_protector.core.git_attributes_parser import GitAttributesParser


class TestGitAttributesParser(unittest.TestCase):

    def setUp(self):
        self.attributes_content = """
# Sample .gitattributes data for multiple filters
*.secret filter=secretfilter
config/*.conf filter=configfilter
*.data filter=datafilter
database/*.sql filter=sqlfilter
        """
        self.m_open = mock_open(read_data=self.attributes_content)

    def test_parse_patterns(self):
        with patch('builtins.open', self.m_open):
            parser = GitAttributesParser()
            patterns = parser.patterns

            # Assertions to ensure all filters are parsed correctly
            self.assertIn('secretfilter', patterns)
            self.assertIn('configfilter', patterns)
            self.assertIn('datafilter', patterns)
            self.assertIn('sqlfilter', patterns)
            self.assertEqual(patterns['secretfilter'], ['*.secret'])
            self.assertEqual(patterns['configfilter'], ['config/*.conf'])
            self.assertEqual(patterns['datafilter'], ['*.data'])
            self.assertEqual(patterns['sqlfilter'], ['database/*.sql'])

    @patch('glob.glob', side_effect=lambda pattern, recursive: ['/fake/repo/example.data'])
    def test_get_files_for_filter(self, mock_glob):
        with patch('builtins.open', self.m_open):
            parser = GitAttributesParser()
            files = parser.get_files_for_filter('datafilter')

            # Check that the files are correctly identified for the datafilter
            self.assertEqual(files, ['/fake/repo/example.data'])
            mock_glob.assert_called_once()

    def test_get_filter_name_for_file(self):
        with patch('builtins.open', self.m_open):
            parser = GitAttributesParser()
            filter_name = parser.get_filter_name_for_file('/fake/repo/config/app.conf', '/fake/repo')

            # Assert that the correct filter name is returned based on pattern
            self.assertEqual(filter_name, 'configfilter')

    def test_get_secret_files(self):
        with patch('builtins.open', self.m_open), \
                patch('git_secret_protector.core.git_attributes_parser.GitAttributesParser._find_files_matching_patterns',
                      return_value=['/fake/repo/config/app.conf', '/fake/repo/database/test.sql']):
            parser = GitAttributesParser()
            secret_files = parser.get_secret_files()

            # Assert that all secret files from all filters are returned
            self.assertIn('/fake/repo/config/app.conf', secret_files)
            self.assertIn('/fake/repo/database/test.sql', secret_files)


if __name__ == '__main__':
    unittest.main()
