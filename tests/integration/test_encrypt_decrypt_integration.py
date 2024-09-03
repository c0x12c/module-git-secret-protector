import logging
import os
import subprocess
import tempfile
import unittest
from git_secret_protector.encryption_manager import EncryptionManager
from git_secret_protector.aes_key_manager import AesKeyManager
from git_secret_protector.git_attributes_parser import GitAttributesParser


class TestGitSecretProtectorIntegration(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory to initialize a git repository
        self.test_dir = tempfile.TemporaryDirectory()
        self.repo_dir = self.test_dir.name

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

        # Instantiate the key manager and setup AES key and IV for encryption
        self.aes_key_manager = AesKeyManager()
        filter_name = 'secretfilter'
        self.aes_key_manager.setup_aes_key_and_iv(filter_name)

    def tearDown(self):
        # Clean up the temporary directory after the test
        os.chdir('/')
        self.test_dir.cleanup()

        # Clean up AES key and IV from SSM
        try:
            print('Clean SSM parameters for filter: secretfilter')
            # self.aes_key_manager.destroy_aes_key_and_iv('secretfilter')
        except Exception as e:
            logging.error(f"Error during cleanup of SSM parameters: {e}")

    def test_encryption_and_decryption(self):
        # Instantiate the key manager and generate a key and IV
        aes_key_manager = AesKeyManager()
        filter_name = 'secretfilter'

        # Setup AES key and IV for encryption
        aes_key_manager.setup_aes_key_and_iv(filter_name)
        aes_key, iv = aes_key_manager.retrieve_key_and_iv(filter_name)

        # Instantiate the encryption manager
        git_attributes_parser = GitAttributesParser()
        encryption_manager = EncryptionManager(aes_key, iv, git_attributes_parser)

        # Encrypt the files
        encryption_manager.encrypt(filter_name=filter_name)

        # Verify that 'secrets/file1.secret' file is encrypted
        with open('secrets/file1.secret', 'rb') as f:
            data = f.read()
            self.assertTrue(data.startswith(b'ENCRYPTED'), f"File secrets/file1.secret was not encrypted properly.")

        # Verify that 'secrets/file1.secret' file is encrypted
        with open('config/app.conf', 'rb') as f:
            data = f.read()
            self.assertFalse(data.startswith(b'ENCRYPTED'), f"File config/app.conf should not be encrypted.")

        # Decrypt the files
        encryption_manager.decrypt(filter_name=filter_name)

        # Verify that files are decrypted to their original content
        for filename, original_content in self.sample_files.items():
            with open(filename, 'r') as f:
                content = f.read()
                self.assertEqual(content, original_content, f"File {filename} was not decrypted correctly.")


if __name__ == '__main__':
    unittest.main()
