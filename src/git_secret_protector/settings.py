import configparser
import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    config_file: str = '.git_secret_protector/config.ini'
    base_dir: str = '.git_secret_protector'
    cache_dir: str = field(init=False)
    log_dir: str = field(init=False)
    module_name: str = 'git-secret-protector'
    log_file: str = field(init=False)
    log_level: str = 'INFO'
    log_max_size: int = 10485760  # 10MB
    log_backup_count: int = 3
    config: configparser.ConfigParser = field(default_factory=configparser.ConfigParser, init=False)

    def __post_init__(self):
        self.cache_dir = os.path.join(self.base_dir, 'cache')
        self.log_dir = os.path.join(self.base_dir, 'logs')
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


def get_settings():
    return Settings()
