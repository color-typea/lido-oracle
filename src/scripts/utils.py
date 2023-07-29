import sys
from enum import Enum

from src.typings import BlockRoot, BlockStamp
from src.utils.blockstamp import build_blockstamp


class Chain(Enum):
    MAINNET = "mainnet"
    GOERLI = "goerli"


def get_last_finalized_slot(cc) -> BlockStamp:
    block_root = BlockRoot(cc.get_block_root('finalized').root)
    block_details = cc.get_block_details(block_root)
    return build_blockstamp(block_details)
