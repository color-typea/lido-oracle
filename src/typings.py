from dataclasses import dataclass
from enum import StrEnum
from typing import NewType, Optional

from eth_typing import HexStr


class OracleModule(StrEnum):
    ACCOUNTING = 'accounting'
    EJECTOR = 'ejector'


EpochNumber = NewType('EpochNumber', int)

StateRoot = NewType('StateRoot', HexStr)
BlockRoot = NewType('BlockRoot', HexStr)
SlotNumber = NewType('SlotNumber', int)

BlockHash = NewType('BlockHash', HexStr)
BlockNumber = NewType('BlockNumber', int)

Gwei = NewType('Gwei', int)


@dataclass(frozen=True)
class BlockStamp:
    block_root: BlockRoot
    state_root: StateRoot
    slot_number: SlotNumber
    block_hash: BlockHash
    block_number: BlockNumber
    # Ref slot could differ from slot_number if ref_slot was missed slot_number will be previous first non-missed slot
    ref_slot: SlotNumber
    # ref_epoch could be empty if we do not know chain configs when generating this timestamp
    ref_epoch: Optional[EpochNumber]
