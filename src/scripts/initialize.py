from typing import cast, Tuple
from src import variables
from src.metrics.logging import logging
from src.web3py.extensions import (
    LidoContracts,
    TransactionUtils,
    ConsensusClientModule,
    KeysAPIClientModule,
    LidoValidatorsProvider,
    FallbackProviderModule
)
from src.web3py.typings import Web3

from src.web3py.contract_tweak import tweak_w3_contracts

logger = logging.getLogger()


def initialize_chain_providers(check_chain_ids = True, lido_contracts_module = None) -> Tuple[Web3, ConsensusClientModule]:
    logger.info({'msg': 'Initialize multi web3 provider.'})
    web3 = Web3(
        FallbackProviderModule(
            variables.EXECUTION_CLIENT_URI,
            request_kwargs={'timeout': variables.HTTP_REQUEST_TIMEOUT_EXECUTION}
        )
    )

    logger.info({'msg': 'Modify web3 with custom contract function call.'})
    tweak_w3_contracts(web3)

    logger.info({'msg': 'Initialize consensus client.'})
    cc = ConsensusClientModule(variables.CONSENSUS_CLIENT_URI, web3)

    logger.info({'msg': 'Initialize keys api client.'})
    kac = KeysAPIClientModule(variables.KEYS_API_URI, web3)

    if check_chain_ids:
        check_providers_chain_ids(web3, cc, kac)

    lido_contracts_module = lido_contracts_module if lido_contracts_module is not None else LidoContracts

    web3.attach_modules(
        {
            'lido_contracts': lido_contracts_module,
            'lido_validators': LidoValidatorsProvider,
            'transaction': TransactionUtils,
            'cc': lambda: cc,  # type: ignore[dict-item]
            'kac': lambda: kac,  # type: ignore[dict-item]
        }
    )
    return web3, cc

def check_providers_chain_ids(web3: Web3, cc: ConsensusClientModule, kac: KeysAPIClientModule):
    keys_api_chain_id = kac.check_providers_consistency()
    consensus_chain_id = cc.check_providers_consistency()
    execution_chain_id = cast(FallbackProviderModule, web3.provider).check_providers_consistency()

    if execution_chain_id == consensus_chain_id == keys_api_chain_id:
        return

    raise ValueError('Different chain ids detected:\n'
                     f'Execution chain id: {execution_chain_id}\n'
                     f'Consensus chain id: {consensus_chain_id}\n'
                     f'Keys API chain id: {keys_api_chain_id}\n')