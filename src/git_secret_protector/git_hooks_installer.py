import os


class GitHooksInstaller:
    def setup_hooks(self):
        self.setup_pre_commit_hook()
        self.setup_post_checkout_hook()

    @staticmethod
    def setup_pre_commit_hook():
        hook_path = '.git/hooks/pre-commit'
        with open(hook_path, 'w') as f:
            f.write("#!/bin/bash\npython main.py encrypt\n")
        os.chmod(hook_path, 0o755)

    @staticmethod
    def setup_post_checkout_hook():
        hook_path = '.git/hooks/post-checkout'
        with open(hook_path, 'w') as f:
            f.write("#!/bin/bash\npython main.py decrypt\n")
        os.chmod(hook_path, 0o755)
