import configparser
import os
from dataclasses import dataclass, field

BASE_DIR = '.git_secret_protector'

@dataclass
class Settings:
    # Singleton instance variable
    _instance: 'Settings' = field(default=None, init=False, repr=False)

    config_file: str = os.path.join(BASE_DIR, 'config.ini')
    cache_dir: str = os.path.join(BASE_DIR, 'cache')
    log_dir: str = os.path.join(BASE_DIR, 'logs')
    module_name: str = 'git-secret-protector'
    log_file: str =  field(init=False)
    log_level: str = 'INFO'
    log_max_size: int = 10485760  # 10MB
    log_backup_count: int = 3
    config: configparser.ConfigParser = field(default_factory=configparser.ConfigParser, init=False)

    def __post_init__(self):
        self.log_file = os.path.join(self.log_dir, 'git_secret_protector.log')
        self._load_config()

    def _load_config(self):
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
            self.module_name = self.config.get('DEFAULT', 'module_name', fallback=self.module_name)
            self.log_file = self.config.get('DEFAULT', 'log_file', fallback=self.log_file)
            self.log_level = self.config.get('DEFAULT', 'log_level', fallback=self.log_level)
            self.log_max_size = self.config.getint('DEFAULT', 'log_max_size', fallback=self.log_max_size)
            self.log_backup_count = self.config.getint('DEFAULT', 'log_backup_count', fallback=self.log_backup_count)

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance


def get_settings():
    return Settings.get_instance()
