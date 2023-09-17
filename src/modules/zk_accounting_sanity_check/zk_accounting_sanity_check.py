import tempfile
from functools import lru_cache
from typing import io, Optional

import ssz
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3.types import TxParams, Wei

from components.eth_consensus_layer_ssz import BeaconState
from src.metrics.prometheus.duration_meter import duration_meter
from src.modules.submodules.consensus import ReportableModuleWithConsensusClient
from src.modules.submodules.oracle_module import BaseModule, ModuleExecuteDelay
from src.modules.zk_accounting_sanity_check.eth_consensus_layer_ssz import Balances
from src.modules.zk_accounting_sanity_check.proof_producer import (
    ProofProducer, CircuitInput, PublicInput, PrivateInput
)
from src.modules.zk_accounting_sanity_check.typings import OracleReport, OracleProof, OracleReportData
from src.utils.slot import get_reference_blockstamp
from src.utils.web3converter import Web3Converter
from src.web3py.contract_tweak import Contract
from src.web3py.extensions.beacon_state import BeaconStateClientModule
from src.web3py.typings import Web3
from src.metrics.logging import logging
from src.typings import SlotNumber, BlockStamp, ReferenceBlockStamp

logger = logging.getLogger()


class ZKAccountingSanityCheck(BaseModule, ReportableModuleWithConsensusClient):
    w3: Web3
    _proof_producer: ProofProducer

    LOGGER = logging.getLogger(__name__ + ".ZKAccountingSanityCheck")

    report_contract: Contract
    CONTRACT_VERSION = 1

    def __init__(self, web3: Web3, proof_producer: ProofProducer):
        super().__init__(web3)
        self.w3 = web3
        self._proof_producer = proof_producer
        self.refresh_contracts()

    # ----- Implementing abstract methods -----
    def execute_module(self, last_finalized_blockstamp: BlockStamp) -> ModuleExecuteDelay:
        report_blockstamp = self.get_blockstamp_for_report(last_finalized_blockstamp)

        if not report_blockstamp:
            return ModuleExecuteDelay.NEXT_FINALIZED_EPOCH

        self.process_report(report_blockstamp)
        return ModuleExecuteDelay.NEXT_SLOT

    def refresh_contracts(self):
        self.report_contract = self.w3.lido_contracts.zktvl_oracle_contract

    @lru_cache(maxsize=1)
    @duration_meter()
    def build_report(self, blockstamp: ReferenceBlockStamp) -> tuple:
        report_data = self._calculate_report(blockstamp)
        logger.info({'msg': 'Calculate report for accounting module.', 'value': report_data})
        return report_data.as_tuple()

    def is_reporting_allowed(self, blockstamp: ReferenceBlockStamp) -> bool:
        return True

    def is_contract_reportable(self, blockstamp: BlockStamp) -> bool:
        return True

    @lru_cache(maxsize=1)
    def _get_consensus_contract_address(self, blockstamp: BlockStamp) -> ChecksumAddress:
        return self.w3.lido_contracts.accounting_oracle.functions.getConsensusContract().call(
            block_identifier=blockstamp.block_number
        )

    def get_blockstamp_for_report(self, last_finalized_blockstamp: BlockStamp) -> Optional[ReferenceBlockStamp]:
        """
        Get blockstamp that should be used to build and send report for current frame.
        Returns:
            Non-missed reference slot blockstamp in case contract is reportable.
        """
        latest_blockstamp = self._get_latest_blockstamp()

        if not self._check_contract_versions(latest_blockstamp):
            logger.info(
                {
                    'msg': 'Oracle\'s version is higher than contract and/or consensus version. '
                           'Skipping report. Waiting for Contracts to be updated.',
                }
            )
            return None

        # Check if contract is currently reportable
        if not self.is_contract_reportable(latest_blockstamp):
            logger.info({'msg': 'Contract is not reportable.'})
            return None

        chain_config = self.get_chain_config(last_finalized_blockstamp)
        frame_config = self.get_frame_config(last_finalized_blockstamp)
        current_frame = self.get_current_frame(last_finalized_blockstamp)

        converter = Web3Converter(chain_config, frame_config)

        bs = get_reference_blockstamp(
            cc=self.w3.cc,
            ref_slot=current_frame.ref_slot,
            ref_epoch=converter.get_epoch_by_slot(current_frame.ref_slot),
            last_finalized_slot_number=last_finalized_blockstamp.slot_number,
        )
        if self._report_already_submitted(bs):
            return None

        logger.info({'msg': 'Calculated blockstamp for report.', 'value': bs})
        return bs

    # ----- End: Implementing abstract methods -----

    def _calculate_report(self, blockstamp: ReferenceBlockStamp) -> OracleReport:
        lido_withdrawal_credentials = self._get_lido_withdrawal_credentials(blockstamp)

        with tempfile.NamedTemporaryFile(mode="w+b") as beacon_state_temp_file:
            self.LOGGER.info({"msg": f"Fetching beacon state for slot {blockstamp.ref_slot}"})
            self._download_beacon_state(blockstamp.ref_slot, beacon_state_temp_file)
            # rewind the stream to the start
            beacon_state_temp_file.seek(0)

            beacon_state = ssz.decode(beacon_state_temp_file.read(), BeaconState)

        self.LOGGER.debug({"msg": f"Fetched beacon state for slot {beacon_state.slot}"})
        report = self._build_report_data(blockstamp, beacon_state, lido_withdrawal_credentials)
        proof = self._build_proof(blockstamp, beacon_state, lido_withdrawal_credentials, report)

        return OracleReport(report, proof)

    def _get_lido_withdrawal_credentials(self, blockstamp: BlockStamp) -> HexBytes:
        self.LOGGER.info({'msg': 'Fetching Lido withdrawal credentials'})
        lido_withdrawal_credentials = self.w3.lido_contracts.staking_router.functions.getWithdrawalCredentials(
        ).call(
            block_identifier=blockstamp.block_number,
        )
        self.LOGGER.debug({'msg': 'Fetch Lido withdrawal credentials.', 'value': lido_withdrawal_credentials})
        return HexBytes(lido_withdrawal_credentials)

    def _download_beacon_state(self, slot: SlotNumber, destination: io.BinaryIO):
        self.LOGGER.info({"msg": f"Downloading Beacon State for {slot} to {destination}"})
        self.w3.bsc.load_beacon_state(slot, destination)
        self.LOGGER.debug({"msg": f"Downloaded Beacon State for {slot} to {destination}"})

    def _build_report_data(
            self, blockstamp: ReferenceBlockStamp, beacon_state: BeaconState, withdrawal_credentials: HexBytes
    ) -> OracleReportData:
        self.LOGGER.info({"msg": f"Building oracle report", "slot": blockstamp.ref_slot})
        block_epoch = blockstamp.ref_epoch
        balance, active, exited = 0, 0, 0
        for (idx, validator) in enumerate(beacon_state.validators):
            if validator.withdrawal_credentials != withdrawal_credentials:
                continue

            balance += beacon_state.balances[idx]
            if validator.exit_epoch <= block_epoch:
                exited += 1
            if validator.activation_eligibility_epoch <= block_epoch:
                active += 1

        report = OracleReportData(
            slot=blockstamp.slot_number,
            epoch=block_epoch,
            lidoWithdrawalCredentials=withdrawal_credentials,
            allLidoValidators=active,
            exitedValidators=exited,
            totalValueLocked=balance
        )
        self.LOGGER.debug({"msg": f"Built oracle report", "value": report.as_dict()})
        return report

    def _build_proof(
            self, blockstamp: ReferenceBlockStamp, beacon_state: BeaconState, withdrawal_credentials: HexBytes,
            report_data: OracleReportData
    ) -> OracleProof:
        self.LOGGER.info({"msg": f"Building oracle ZK-proof for slot {blockstamp.slot_number}"})
        balances_hash = HexBytes(ssz.get_hash_tree_root(beacon_state.balances))
        validators_hash = HexBytes(ssz.get_hash_tree_root(beacon_state.validators))
        beacon_state_hash = HexBytes(ssz.get_hash_tree_root(beacon_state))

        circuit_input = CircuitInput(
            PublicInput(
                withdrawal_credentials,
                balances_hash,
                validators_hash,
                beacon_state_hash,
                HexBytes(blockstamp.block_hash),
                blockstamp.ref_slot,
                blockstamp.ref_epoch,
            ),
            PrivateInput(
                beacon_state.validators,
                beacon_state.balances,
                # TODO: compute real inclusion proofs
                [HexBytes(idx.to_bytes(32)) for idx in range(6)],
                [HexBytes(idx.to_bytes(32)) for idx in range(6, 12)],
                [HexBytes(idx.to_bytes(32)) for idx in range(12, 15)],
            ),
            report_data
        )
        zk_proof = self._proof_producer.generate_proof(circuit_input)

        proof = OracleProof(
            balances_hash=balances_hash,
            validators_hash=validators_hash,
            beacon_state_hash=beacon_state_hash,
            beacon_block_hash=HexBytes(blockstamp.block_hash),
            zk_proof=HexBytes(zk_proof)
        )
        self.LOGGER.debug({"msg": f"Built oracle ZK-proof", "value": proof.as_dict()})
        return proof

    def _report_already_submitted(self, blockstamp: ReferenceBlockStamp) -> bool:
        # TODO: read report from report_contract for the blockstamp.ref_slot - don't submit if already exists
        return False
