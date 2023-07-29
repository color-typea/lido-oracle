from typing import Optional

from src.scripts.initialize import initialize_chain_providers
from src.scripts.utils import Chain, get_last_finalized_slot
from src.metrics.logging import logging
from src.modules.accounting.accounting import Accounting
from src.modules.accounting.minimal_accounting import MinimalAccounting
from src.modules.ejector.ejector import Ejector
from src.modules.submodules.consensus import ConsensusModule
from src.typings import OracleModule, SlotNumber
from src.utils import slot as slot_utils
from src.utils.web3converter import Web3LightConverter
from src.web3py.typings import Web3

logger = logging.getLogger()


def get_module(web3: Web3, module_name: OracleModule) -> ConsensusModule:
    logger.info({"msg": f"Initialize module {module_name}"})
    if module_name == OracleModule.ACCOUNTING:
        logger.info({'msg': 'Initialize Accounting module.'})
        instance = Accounting(web3)
    elif module_name == OracleModule.EJECTOR:
        logger.info({'msg': 'Initialize Ejector module.'})
        instance = Ejector(web3)  # type: ignore[assignment]
    elif module_name == OracleModule.ACCOUNTING_MIN:
        logger.info({'msg': 'Initialize minimal accounting module.'})
        instance = MinimalAccounting(web3)
    else:
        raise ValueError(f'Unexpected arg: {module_name=}.')

    logger.info({'msg': 'Sanity checks.'})
    instance.check_contract_configs()

    return instance

# Note: _main is to indicate that this should not be imported directly, the "actual" main is in the __init__.py
def _main(module: OracleModule, slot: Optional[int]):
    web3, cc = initialize_chain_providers()
    module = get_module(web3, module)

    last_finalized = get_last_finalized_slot(web3.cc)
    converter = Web3LightConverter(module.get_chain_config(last_finalized))

    if slot is None:
        target_slot = last_finalized.slot_number
    else:
        target_slot = SlotNumber(slot)

    logger.info({"msg": f"Getting reference blockstamp for slot {target_slot}"})
    reference_blockstamp = slot_utils.get_reference_blockstamp(
        web3.cc,
        target_slot,
        last_finalized.slot_number,
        converter.get_epoch_by_slot(target_slot)
    )

    logger.info({"msg": f"Building report for {reference_blockstamp}"})
    report = module.build_report(reference_blockstamp)
    print(report)

