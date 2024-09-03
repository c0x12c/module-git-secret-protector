import logging
import os

logger = logging.getLogger(__name__)


class GitHooksInstaller:
    def __init__(self, repo_path='.'):
        self.repo_path = repo_path
        self.hooks_path = os.path.join(self.repo_path, '.git', 'hooks')

    def setup_hooks(self):
        self._create_pre_commit_hook()
        self._create_post_checkout_hook()
        logger.info("Git hooks have been installed successfully.")

    def _create_pre_commit_hook(self):
        hook_script = """#!/bin/sh
        # Pre-commit hook to encrypt files before commit
        git_secret_protector encrypt
        """

        self._write_hook_script('pre-commit', hook_script)

    def _create_post_checkout_hook(self):
        hook_script = """#!/bin/sh
        # Post-checkout hook to decrypt files after checkout
        git_secret_protector decrypt
        """

        self._write_hook_script('post-checkout', hook_script)

    def _write_hook_script(self, hook_name, script_content):
        hook_file = os.path.join(self.hooks_path, hook_name)
        with open(hook_file, 'w') as f:
            f.write(script_content)
        os.chmod(hook_file, 0o755)  # Make the script executable
        logger.info(f"{hook_name} hook installed.")
