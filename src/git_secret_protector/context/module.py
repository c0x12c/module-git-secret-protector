import injector

from git_secret_protector.core.git_attributes_parser import GitAttributesParser
from git_secret_protector.core.output import Output
from git_secret_protector.crypto.aes_key_manager import AesKeyManager


class GitSecretProtectorModule(injector.Module):
    _injector = None
    _output = None

    def configure(self, binder):
        binder.bind(AesKeyManager, to=AesKeyManager, scope=injector.singleton)
        binder.bind(
            GitAttributesParser, to=GitAttributesParser, scope=injector.singleton
        )
        binder.bind(Output, to=self._output or Output(), scope=injector.singleton)

    @classmethod
    def set_output(cls, output):
        cls._output = output
        cls._injector = None  # force rebuild so the binding picks up the instance

    @classmethod
    def get_injector(cls):
        if cls._injector is None:
            cls._injector = injector.Injector(GitSecretProtectorModule())
        return cls._injector
