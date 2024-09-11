import configparser
import logging
import os
import subprocess
import tempfile
import unittest

from git_secret_protector.context.module import GitSecretProtectorModule
from git_secret_protector.core.settings import StorageType
from git_secret_protector.crypto.aes_key_manager import AesKeyManager
from git_secret_protector.services.encryption_manager import EncryptionManager


class TestGitSecretProtectorIntegrationWithGcpSecret(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory to initialize a git repository
        self.test_dir = tempfile.TemporaryDirectory()
        self.repo_dir = self.test_dir.name
        self.module_dir = os.path.join(self.repo_dir, '.git_secret_protector')
        os.makedirs(self.module_dir, exist_ok=True)

        # Initialize a git repository
        subprocess.run(['git', 'init', self.repo_dir], check=True)

        # Change the working directory to the repo directory
        os.chdir(self.repo_dir)

        # Write a sample .gitattributes file
        self.gitattributes_content = """
# Sample .gitattributes data
secrets/* filter=secretfilter
config/*.conf filter=configfilter
        """
        with open('.gitattributes', 'w') as f:
            f.write(self.gitattributes_content)

        # Add and commit the .gitattributes file
        subprocess.run(['git', 'add', '.gitattributes'], check=True)
        subprocess.run(['git', 'commit', '-m', 'Add .gitattributes'], check=True)

        # Create sample files and necessary directories
        self.sample_files = {
            'secrets/file1.secret': 'This is a secret file.',
            'config/app.conf': 'Configuration content.'
        }
        for filename, content in self.sample_files.items():
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, 'w') as f:
                f.write(content)

        # Add and commit the sample files
        subprocess.run(['git', 'add', '.'], check=True)
        subprocess.run(['git', 'commit', '-m', 'Add sample files'], check=True)

        # Create a config.ini file in the module directory
        config = configparser.ConfigParser()
        config['DEFAULT'] = {
            'module_name': 'git-secret-protector-test',
            'cache_dir': '.git_secret_protector/cache',
            'log_file': '.git_secret_protector/logs/git_secret_protector.log',
            'storage_type': StorageType.GCP_SECRET.value
        }
        with open(os.path.join(self.module_dir, 'config.ini'), 'w') as configfile:
            config.write(configfile)

        module_injector = GitSecretProtectorModule.get_injector()
        self.encryption_manager = module_injector.get(EncryptionManager)
        self.aes_key_manager = module_injector.get(AesKeyManager)

    def tearDown(self):
        print('Cleaning up')
        # Clean up the temporary directory after the test
        os.chdir('/')
        self.test_dir.cleanup()

        # Clean up AES key and IV from GCloud Secret
        try:
            print('Clean GCloud Secret for filter: secretfilter')
            self.aes_key_manager.destroy_aes_key_and_iv('secretfilter')
        except Exception as e:
            logging.error(f"Error during cleanup of GCloud Secret: {e}")

    def test_encryption_and_decryption(self):
        filter_name = 'secretfilter'
        self.encryption_manager.setup_aes_key(filter_name)
        self.encryption_manager.encrypt_files(filter_name=filter_name)

        # Verify that 'secrets/file1.secret' file is encrypted
        with open('secrets/file1.secret', 'rb') as f:
            data = f.read()
            self.assertTrue(data.startswith(b'ENCRYPTED'), f"File secrets/file1.secret was not encrypted properly.")

        # Verify that 'secrets/file1.secret' file is encrypted
        with open('config/app.conf', 'rb') as f:
            data = f.read()
            self.assertFalse(data.startswith(b'ENCRYPTED'), f"File config/app.conf should not be encrypted.")

        # Decrypt the files
        self.encryption_manager.decrypt_files(filter_name=filter_name)

        # Verify that files are decrypted to their original content
        for filename, original_content in self.sample_files.items():
            with open(filename, 'r') as f:
                content = f.read()
                self.assertEqual(content, original_content, f"File {filename} was not decrypted correctly.")


if __name__ == '__main__':
    unittest.main()
