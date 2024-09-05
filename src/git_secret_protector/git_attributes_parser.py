import fnmatch
import glob
import logging
import os
import re

from git_secret_protector.settings import get_settings

logger = logging.getLogger(__name__)


class GitAttributesParser:
    def __init__(self):
        settings = get_settings()
        git_attributes_file = os.path.join(settings.base_dir, '.gitattributes')

        self.git_attributes_file = git_attributes_file
        self.patterns = self._parse_patterns()

    def _parse_patterns(self):
        """Parse the .gitattributes file to extract patterns associated with filters."""
        patterns = {}
        with open(self.git_attributes_file, 'r') as file:
            for line in file:
                match = re.search(r'(.+)\s+filter=(\S+)', line)
                if match:
                    pattern = match.group(1).strip()
                    filter_name = match.group(2).strip()
                    if filter_name not in patterns:
                        patterns[filter_name] = []
                    patterns[filter_name].append(pattern)
        return patterns

    def _find_files_matching_patterns(self, patterns, repo_root='.'):
        """Helper method to find files matching given patterns using glob."""
        matched_files = set()  # Using a set to avoid duplicates
        for pattern in patterns:
            files = glob.glob(os.path.join(repo_root, pattern), recursive=True)
            matched_files.update(files)
        return list(matched_files)

    def get_secret_files(self, repo_root='.'):
        """Return all files matching any of the filter patterns."""
        secret_files = set()
        for patterns in self.patterns.values():
            secret_files.update(self._find_files_matching_patterns(patterns, repo_root))
        return list(secret_files)

    def get_files_for_filter(self, filter_name, repo_root='.'):
        """Return all files matching the patterns for a specific filter name."""
        patterns = self.patterns.get(filter_name, [])
        return self._find_files_matching_patterns(patterns, repo_root)

    def get_filter_names(self):
        """Return a list of unique filter names from the .gitattributes file."""
        return list(self.patterns.keys())

    def get_filter_name_for_file(self, file_name, repo_root='.'):
        """Return the filter name that matches the given file name based on .gitattributes patterns."""
        for filter_name, patterns in self.patterns.items():
            for pattern in patterns:
                if fnmatch.fnmatch(os.path.relpath(file_name, repo_root), pattern):
                    return filter_name
        return None
