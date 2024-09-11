import injector

from git_secret_protector.core.git_attributes_parser import GitAttributesParser
from git_secret_protector.crypto.aes_key_manager import AesKeyManager


class GitSecretProtectorModule(injector.Module):
    _injector: 'injector.Injector' = None

    def configure(self, binder):
        binder.bind(AesKeyManager, to=AesKeyManager, scope=injector.singleton)
        binder.bind(GitAttributesParser, to=GitAttributesParser, scope=injector.singleton)

    @classmethod
    def get_injector(cls):
        if cls._injector is None:
            cls._injector = injector.Injector(GitSecretProtectorModule())
        return cls._injector
