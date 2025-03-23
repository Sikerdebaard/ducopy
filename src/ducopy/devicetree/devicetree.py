from ducopy.devicetree.communicationboard import CommunicationBoard, ConnectivityBoard
from loguru import logger

_supported_boards = [ConnectivityBoard]


def detect(url: str) -> CommunicationBoard:
    for BoardAdapter in _supported_boards:
        if BoardAdapter(url).detect(url):
            board = BoardAdapter(url)
            logger.debug(f"Detected {board.name()}")

            return board

    return None


def list_devicetree(url: str) -> CommunicationBoard | None:
    board = detect(url)

    if not board:
        return None

    box = board.get_box()
    del box

    return board
