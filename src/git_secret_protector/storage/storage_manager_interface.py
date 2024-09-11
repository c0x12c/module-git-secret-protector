from abc import ABC, abstractmethod


class StorageManagerInterface(ABC):

    @abstractmethod
    def store(self, name: str, value: str) -> None:
        pass

    @abstractmethod
    def retrieve(self, name: str) -> str:
        pass

    @abstractmethod
    def delete(self, name: str) -> None:
        pass

    @abstractmethod
    def exists(self, name: str) -> bool:
        pass

    @abstractmethod
    def parameter_name(self, module_name: str, filter_name: str) -> str:
        pass
