import configparser
import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    BASE_DIR_LOOKUP_FOLDER = ".git"

    _instance: 'Settings' = field(default=None, init=False, repr=False, compare=False)
    module_folder: str = '.git_secret_protector'
    base_dir: str = field(init=False)
    module_dir: str = field(init=False)
    config_file: str = field(init=False)
    cache_dir: str = field(init=False)
    log_dir: str = field(init=False)
    module_name: str = 'git-secret-protector'
    log_file: str = field(init=False)
    log_level: str = 'INFO'
    log_max_size: int = 10485760  # 10MB
    log_backup_count: int = 3
    config: configparser.ConfigParser = field(init=False)

    def __post_init__(self):
        self.base_dir = self.find_base_dir()
        self.module_dir = os.path.join(self.base_dir, self.module_folder)
        self.config_file = os.path.join(self.module_dir, 'config.ini')
        self.cache_dir = os.path.join(self.module_dir, 'cache')
        self.log_dir = os.path.join(self.module_dir, 'logs')
        self.log_file = os.path.join(self.log_dir, 'git_secret_protector.log')
        self.config = configparser.ConfigParser()
        self._load_config()

    def find_base_dir(self):
        current_dir = os.getcwd()
        while current_dir != os.path.dirname(current_dir):  # Traverse up to the root directory
            possible_dir = os.path.join(current_dir, Settings.BASE_DIR_LOOKUP_FOLDER)
            if os.path.exists(possible_dir):
                return current_dir
            current_dir = os.path.dirname(current_dir)
        raise FileNotFoundError(
            "The git-secret-protector module folder was not found in any ascendant directories. Please ensure the module is set up correctly.")

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
