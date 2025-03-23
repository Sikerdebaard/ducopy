from abc import abstractmethod
from ducopy.devicetree.box import Box


class AbstractCommunicationBoard:
    @abstractmethod
    def detect(self, *args: tuple, **kwargs: dict) -> bool:
        pass

    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def get_box(self) -> Box:
        pass
