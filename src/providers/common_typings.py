from typing import Literal, Union

from src.typings import SlotNumber, BlockRoot

LiteralState = Literal['head', 'genesis', 'finalized', 'justified']
StateId = Union[SlotNumber, BlockRoot]
StateIdWithLiteral = Union[StateId, LiteralState]