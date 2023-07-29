import logging
from collections import defaultdict
from src.modules.accounting.typings import (
    AccountingProcessingState,MinimalReportData,
)
from src.metrics.prometheus.duration_meter import duration_meter
from src.services.validator_state import LidoValidatorStateService
from src.modules.submodules.consensus import ConsensusModule
from src.modules.submodules.oracle_module import BaseModule, ModuleExecuteDelay
from src.services.bunker import BunkerService
from src.typings import BlockStamp, Gwei, ReferenceBlockStamp
from src.utils.abi import named_tuple_to_dataclass
from src.utils.cache import global_lru_cache as lru_cache
from src.web3py.typings import Web3
from src.web3py.extensions.lido_validators import StakingModule, NodeOperatorGlobalIndex, StakingModuleId

logger = logging.getLogger(__name__)


class MinimalAccounting(BaseModule, ConsensusModule):
    """
    Accounting module updates the protocol TVL, distributes node-operator rewards, and processes user withdrawal requests.

    Report goes in tree phases:
        - Send report hash
        - Send report data (extra data hash inside)
            Contains information about lido states, last withdrawal request to finalize and exited validators count by module.
        - Send extra data
            Contains stuck and exited validators count by each node operator.
    """
    CONSENSUS_VERSION = 1
    CONTRACT_VERSION = 1

    def __init__(self, w3: Web3):
        self.report_contract = w3.lido_contracts.accounting_oracle
        super().__init__(w3)

        self.lido_validator_state_service = LidoValidatorStateService(self.w3)
        self.bunker_service = BunkerService(self.w3)

    def refresh_contracts(self):
        self.report_contract = self.w3.lido_contracts.accounting_oracle

    def execute_module(self, last_finalized_blockstamp: BlockStamp) -> ModuleExecuteDelay:
        report_blockstamp = self.get_blockstamp_for_report(last_finalized_blockstamp)

        if report_blockstamp:
            self.process_report(report_blockstamp)
            return ModuleExecuteDelay.NEXT_SLOT

        return ModuleExecuteDelay.NEXT_FINALIZED_EPOCH

    def is_reporting_allowed(self, **kwargs):
        return False

    def is_contract_reportable(self, blockstamp: BlockStamp) -> bool:
        return False

    @lru_cache(maxsize=1)
    @duration_meter()
    def build_report(self, blockstamp: ReferenceBlockStamp) -> tuple:
        report_data = self._calculate_report(blockstamp)
        logger.info({'msg': 'Calculate report for accounting module.', 'value': report_data})
        return report_data.as_tuple()

    def is_main_data_submitted(self, blockstamp: BlockStamp) -> bool:
        # Consensus module: if contract got report data (second phase)
        processing_state = self._get_processing_state(blockstamp)
        logger.debug({'msg': 'Check if main data was submitted.', 'value': processing_state.main_data_submitted})
        return processing_state.main_data_submitted

    @lru_cache(maxsize=1)
    def _get_processing_state(self, blockstamp: BlockStamp) -> AccountingProcessingState:
        ps = named_tuple_to_dataclass(
            self.report_contract.functions.getProcessingState().call(block_identifier=blockstamp.block_hash),
            AccountingProcessingState,
        )
        logger.info({'msg': 'Fetch processing state.', 'value': ps})
        return ps

    # ---------------------------------------- Build report ----------------------------------------
    def _calculate_report(self, blockstamp: ReferenceBlockStamp) -> MinimalReportData:
        validators_count, cl_balance = self._get_consensus_lido_state(blockstamp)

        staking_module_ids_list, exit_validators_count_list = self._get_newly_exited_validators_by_modules(blockstamp)

        report_data = MinimalReportData(
            consensus_version=self.CONSENSUS_VERSION,
            ref_slot=blockstamp.ref_slot,
            validators_count=validators_count,
            cl_balance_gwei=cl_balance,
            count_exited_validators=sum(exit_validators_count_list),
        )

        return report_data

    def _get_newly_exited_validators_by_modules(
        self,
        blockstamp: ReferenceBlockStamp,
    ) -> tuple[list[StakingModuleId], list[int]]:
        """
        Calculate exited validators count in all modules.
        Exclude modules without changes from the report.
        """
        staking_modules = self.w3.lido_validators.get_staking_modules(blockstamp)
        exited_validators = self.lido_validator_state_service.get_exited_lido_validators(blockstamp)

        return self.get_updated_modules_stats(staking_modules, exited_validators)

    @staticmethod
    def get_updated_modules_stats(
        staking_modules: list[StakingModule],
        exited_validators_by_no: dict[NodeOperatorGlobalIndex, int],
    ) -> tuple[list[StakingModuleId], list[int]]:
        """Returns exited validators count by node operators that should be updated."""
        module_stats: dict[StakingModuleId, int] = defaultdict(int)

        for (module_id, _), validators_exited_count in exited_validators_by_no.items():
            module_stats[module_id] += validators_exited_count

        return list(module_stats.keys()), list(module_stats.values())

    @lru_cache(maxsize=1)
    def _get_consensus_lido_state(self, blockstamp: ReferenceBlockStamp) -> tuple[int, Gwei]:
        lido_validators = self.w3.lido_validators.get_lido_validators(blockstamp)

        count = len(lido_validators)
        total_balance = Gwei(sum(int(validator.balance) for validator in lido_validators))

        logger.info({'msg': 'Calculate consensus lido state.', 'value': (count, total_balance)})
        return count, total_balance
