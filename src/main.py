import sys
from typing import cast

from prometheus_client import start_http_server
from web3.middleware import simple_cache_middleware

from src import variables
from src.metrics.healthcheck_server import start_pulse_server
from src.metrics.logging import logging
from src.metrics.prometheus.basic import ENV_VARIABLES_INFO, BUILD_INFO
from src.modules.accounting.accounting import Accounting
from src.modules.ejector.ejector import Ejector
from src.modules.checks.checks_module import ChecksModule
from src.modules.zk_accounting_sanity_check.proof_producer import ProofProducerFactory
from src.modules.zk_accounting_sanity_check.zk_accounting_sanity_check import ZKAccountingSanityCheck
from src.typings import OracleModule
from src.utils.build import get_build_info
from src.web3py.extensions import (
    LidoContracts,
    TransactionUtils,
    ConsensusClientModule,
    KeysAPIClientModule,
    LidoValidatorsProvider,
    FallbackProviderModule
)
from src.web3py.extensions.beacon_state import BeaconStateClientModule
from src.web3py.middleware import metrics_collector
from src.web3py.typings import Web3

from src.web3py.contract_tweak import tweak_w3_contracts


logger = logging.getLogger()


def main(module_name: OracleModule):
    build_info = get_build_info()
    logger.info({
        'msg': 'Oracle startup.',
        'variables': {
            **build_info,
            'module': module_name,
            'ACCOUNT': variables.ACCOUNT.address if variables.ACCOUNT else 'Dry',
            'LIDO_LOCATOR_ADDRESS': variables.LIDO_LOCATOR_ADDRESS,
            'MAX_CYCLE_LIFETIME_IN_SECONDS': variables.MAX_CYCLE_LIFETIME_IN_SECONDS,
        },
    })
    ENV_VARIABLES_INFO.info({
        "ACCOUNT": str(variables.ACCOUNT.address) if variables.ACCOUNT else 'Dry',
        "LIDO_LOCATOR_ADDRESS": str(variables.LIDO_LOCATOR_ADDRESS),
        "FINALIZATION_BATCH_MAX_REQUEST_COUNT": str(variables.FINALIZATION_BATCH_MAX_REQUEST_COUNT),
        "MAX_CYCLE_LIFETIME_IN_SECONDS": str(variables.MAX_CYCLE_LIFETIME_IN_SECONDS),
    })
    BUILD_INFO.info(build_info)

    logger.info({'msg': f'Start healthcheck server for Docker container on port {variables.HEALTHCHECK_SERVER_PORT}'})
    start_pulse_server()

    logger.info({'msg': f'Start http server with prometheus metrics on port {variables.PROMETHEUS_PORT}'})
    start_http_server(variables.PROMETHEUS_PORT)

    logger.info({'msg': 'Initialize multi web3 provider.'})
    web3 = Web3(FallbackProviderModule(
        variables.EXECUTION_CLIENT_URI,
        request_kwargs={'timeout': variables.HTTP_REQUEST_TIMEOUT_EXECUTION}
    ))

    logger.info({'msg': 'Modify web3 with custom contract function call.'})
    tweak_w3_contracts(web3)

    logger.info({'msg': 'Initialize consensus client.'})
    cc = ConsensusClientModule(variables.CONSENSUS_CLIENT_URI, web3)

    web3.attach_modules(
        {
            'lido_contracts': LidoContracts,
            'lido_validators': LidoValidatorsProvider,
            'transaction': TransactionUtils,
            'cc': lambda: cc,  # type: ignore[dict-item]
        }
    )

    logger.info({'msg': 'Add metrics middleware for ETH1 requests.'})
    web3.middleware_onion.add(metrics_collector)
    web3.middleware_onion.add(simple_cache_middleware)

    logger.info({'msg': 'Sanity checks.'})

    if module_name == OracleModule.ACCOUNTING:
        logger.info({'msg': 'Initialize keys api client.'})
        # type: ignore[dict-item]
        web3.attach_modules(
            {
                'kac': lambda: KeysAPIClientModule(variables.KEYS_API_URI, web3),
                'bsc': lambda: None
            }
        )
        logger.info({'msg': 'Initialize Accounting module.'})
        instance = Accounting(web3)
    elif module_name == OracleModule.EJECTOR:
        logger.info({'msg': 'Initialize keys api client.'})
        # type: ignore[dict-item]
        web3.attach_modules(
            {
                'kac': lambda: KeysAPIClientModule(variables.KEYS_API_URI, web3),
                'bsc': lambda: None
            }
        )
        logger.info({'msg': 'Initialize Ejector module.'})
        instance = Ejector(web3)  # type: ignore[assignment]
    elif module_name == OracleModule.ZK_ACCOUNTING_SANITY_CHECK:
        logger.info({'msg': 'Initialize Beacon State Client.'})
        # type: ignore[dict-item]
        web3.attach_modules(
            {
                'ksc': lambda: None,
                'bsc': lambda: BeaconStateClientModule(variables.BEACON_STATE_CLIENT_URI, web3),
            }
        )
        logger.info({'msg': 'Initialize Proof Producer.'})
        proof_producer = ProofProducerFactory.create()
        logger.info({'msg': 'Initialize ZKAccountingSanityCheck module.'})
        instance = ZKAccountingSanityCheck(web3, proof_producer)
    else:
        raise ValueError(f'Unexpected arg: {module_name=}.')

    logger.info({'msg': 'Checking provider chain IDs.'})
    web3.check_providers_chain_ids()

    logger.info({'msg': "Checking module's contract configuration."})
    instance.check_contract_configs()

    if variables.DAEMON:
        instance.run_as_daemon()
    else:
        instance.cycle_handler()


def check():
    logger.info({'msg': 'Check oracle is ready to work in the current environment.'})

    return ChecksModule().execute_module()


if __name__ == '__main__':
    module_name_arg = sys.argv[-1]
    if module_name_arg not in iter(OracleModule):
        msg = f'Last arg should be one of {[str(item) for item in OracleModule]}, received {module_name_arg}.'
        logger.error({'msg': msg})
        raise ValueError(msg)

    module = OracleModule(module_name_arg)
    if module == OracleModule.CHECK:
        errors = variables.check_uri_required_variables()
        variables.raise_from_errors(errors)

        sys.exit(check())

    errors = variables.check_all_required_variables()
    variables.raise_from_errors(errors)
    main(module)
