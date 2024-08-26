import configparser
import os


class Settings:
    def __init__(self, config_file='.git_secret_protector/config.ini'):
        self.base_dir = '.git_secret_protector'
        self.cache_dir = os.path.join(self.base_dir, 'cache')
        self.log_dir = os.path.join(self.base_dir, 'logs')
        self.config_file = config_file
        self.config = configparser.ConfigParser()

        # Default values
        self.module_name = 'git-secret-protector'
        self.log_file = os.path.join(self.log_dir, 'git_secret_protector.log')

        # Load configuration from file
        self._load_config()

    def _load_config(self):
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
            self.module_name = self.config.get('DEFAULT', 'module_name', fallback=self.module_name)
            self.log_file = self.config.get('DEFAULT', 'log_file', fallback=self.log_file)


def get_settings():
    return Settings()
