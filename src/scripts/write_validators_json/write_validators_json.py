import json
import os
from typing import Optional, Dict, List

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
from src.web3py.extensions.lido_validators import LidoValidator
from src.web3py.typings import Web3

logger = logging.getLogger()

def validator_to_jsonable_dict(validator: LidoValidator) -> Dict[str, any]:
    return {
        "pubkey": validator.validator.pubkey,
        "withdrawalCredentials": validator.validator.withdrawal_credentials,
        "activationEligibilityEpoch": validator.validator.activation_eligibility_epoch,
        "activationEpoch": validator.validator.activation_epoch,
        "exitEpoch": validator.validator.exit_epoch,
        "balance": validator.balance
    }


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
def _main(chain: Chain, slot: Optional[int], output_filename=None):
    web3, cc = initialize_chain_providers()
    module = MinimalAccounting(web3)

    last_finalized = get_last_finalized_slot(cc)
    converter = Web3LightConverter(module.get_chain_config(last_finalized))

    if slot is None:
        target_slot = last_finalized.slot_number
    else:
        target_slot = SlotNumber(slot)

    logger.info({"msg": f"Getting reference blockstamp for slot {target_slot}"})
    blockstamp = slot_utils.get_reference_blockstamp(
        web3.cc,
        target_slot,
        last_finalized.slot_number,
        converter.get_epoch_by_slot(target_slot)
    )

    lido_validators = web3.lido_validators.get_lido_validators(blockstamp)
    if output_filename is None:
        output_filename = f"lido_validators_{chain.value}_s{blockstamp.slot_number}_b{blockstamp.block_number}.json"

    logger.info({"msg": f"Writing validators to {output_filename}"})

    # quick-and-dirty JSON encoding
    validator_dicts = [validator_to_jsonable_dict(validator) for validator in lido_validators]
    with open(output_filename, "w") as output_file:
        json.dump(validator_dicts, output_file, indent=4)

