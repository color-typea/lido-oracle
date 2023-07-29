import dataclasses
import os
import tempfile
from typing import Optional, io

import ssz
from hexbytes import HexBytes
from web3.types import TxParams, Wei

from src.scripts.paths import PROJECT_ROOT
from src.scripts.beacon_state_report.proof_producer import (
    ProofProducer, PrecomputedProofProducer,
    ProofGeneratorCLIProofProducer
)
from src.utils.slot import get_blockstamp
from src.web3py.contract_tweak import Contract
from src.web3py.extensions.beacon_state import BeaconStateClientModule
from src.web3py.extensions.contracts import LidoZKLLVMMinimalContracts
from src.web3py.typings import Web3
from src import variables, constants
from src.metrics.logging import logging
from src.modules.submodules.typings import ChainConfig
from src.typings import SlotNumber, EpochNumber, BlockStamp, BlockHash
from src.web3py.extensions import ConsensusClientModule
from src.utils.web3converter import Web3LightConverter

from src.scripts.initialize import initialize_chain_providers
from src.scripts.beacon_state_report.eth_consensus_layer_ssz import BeaconState, Balances
from src.scripts.utils import get_last_finalized_slot, Chain

logger = logging.getLogger()

SCRIPT_FOLDER = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_FOLDER = os.path.dirname(SCRIPT_FOLDER)
SRC_FOLDER = os.path.dirname(SCRIPTS_FOLDER)
ORACLE_FOLDER = os.path.dirname(SRC_FOLDER)
# PRECOMPUTED_PROOF = os.path.join(SCRIPT_FOLDER, "proof.bin")
SIZE = "size256"
PRECOMPUTED_PROOF = os.path.join(ORACLE_FOLDER, "../../zkllvm/balances_tree_output/", SIZE, "gates/proof.bin")


class DataclassConvenience:
    def as_tuple(self):
        return tuple(self.as_dict().values())

    def as_dict(self):
        return dataclasses.asdict(self)


@dataclasses.dataclass
class OracleReport(DataclassConvenience):
    slot: SlotNumber
    epoch: EpochNumber
    lidoWithdrawalCredentials: HexBytes
    allLidoValidators: int
    exitedValidators: int
    totalValueLocked: int

    def as_tuple(self):
        return (
            self.slot,
            self.epoch,
            self.lidoWithdrawalCredentials,
            self.allLidoValidators,
            self.exitedValidators,
            self.totalValueLocked,
        )


@dataclasses.dataclass
class OracleProof(DataclassConvenience):
    # beaconBlockHash: BlockHash
    balances_hash: BlockHash
    zk_proof: HexBytes

    def as_tuple(self):
        return (
            self.balances_hash,
            self.zk_proof,
        )

    def as_dict_for_logging(self):
        as_dict = dataclasses.asdict(self)
        as_dict['zk_proof'] = as_dict['zk_proof'].hex()
        as_dict['balances_hash'] = as_dict['balances_hash'].hex()

        del as_dict['zk_proof']
        # as_dict['zk_proof'] = as_dict['zk_proof'][:20] + b'\x01020304' + as_dict['zk_proof'][:-20]

        return as_dict


class Script:
    _web3: Web3
    _cc: ConsensusClientModule
    _bsc: BeaconStateClientModule
    _chain_config: ChainConfig
    _converter: Web3LightConverter

    LOGGER = logging.getLogger(__name__ + ".Script")

    report_contract: Contract
    CONTRACT_VERSION = 1

    def __init__(
            self, web3: Web3, cc: ConsensusClientModule, bsc: BeaconStateClientModule, proof_producer: ProofProducer
    ):
        self._web3 = web3
        self._cc = cc
        self._bsc = bsc
        self._init_chain_config()
        self._converter = Web3LightConverter(self._chain_config)
        self.report_contract = self._web3.lido_contracts.zktvl_oracle_contract
        self._proof_producer = proof_producer

    def _init_chain_config(self):
        # Chain config should be read from ConsensusModule. However this oracle+contract pair do not need
        # consensus, so the mechanism would need to be different.
        # TODO: "unhardcode" chain config
        if variables.CHAIN == Chain.MAINNET.value:
            self._chain_config = ChainConfig(slots_per_epoch=32, seconds_per_slot=12, genesis_time=1606824023)
        elif variables.CHAIN == Chain.GOERLI.value:
            self._chain_config = ChainConfig(slots_per_epoch=32, seconds_per_slot=12, genesis_time=1616508000)
        else:
            raise ValueError("Cannot initialize Chain config - unknown chain is used")

    def run(self, blockstamp: BlockStamp, dry_run=False):
        lido_withdrawal_credentials = self._get_lido_withdrawal_credentials(blockstamp)

        with tempfile.NamedTemporaryFile(mode="w+b") as beacon_state_temp_file:
            self.LOGGER.info({"msg": f"Fetching beacon state for slot {blockstamp.slot_number}"})
            self._download_beacon_state(blockstamp.slot_number, beacon_state_temp_file)
            # rewind the stream to the start
            beacon_state_temp_file.seek(0)

            beacon_state = ssz.decode(beacon_state_temp_file.read(), BeaconState)

        self.LOGGER.debug({"msg": f"Fetched beacon state for slot {beacon_state.slot}"})
        report = self._build_report(blockstamp, beacon_state, lido_withdrawal_credentials)
        proof = self.build_proof(blockstamp, beacon_state)

        if not dry_run:
            self._submit_report(report, proof)
        else:
            self.LOGGER.info({"msg": "[DRY RUN] Skipping sending the report"})

    def _get_lido_withdrawal_credentials(self, blockstamp: BlockStamp) -> HexBytes:
        self.LOGGER.info({'msg': 'Fetching Lido withdrawal credentials'})
        lido_withdrawal_credentials = self._web3.lido_contracts.staking_router.functions.getWithdrawalCredentials(
        ).call(
            # block_identifier=blockstamp.block_hash,
        )
        self.LOGGER.debug({'msg': 'Fetch Lido withdrawal credentials.', 'value': lido_withdrawal_credentials})
        return HexBytes(lido_withdrawal_credentials)

    def _download_beacon_state(self, slot: SlotNumber, destination: io.BinaryIO):
        self.LOGGER.info({"msg": f"Downloading Beacon State for {slot} to {destination}"})
        self._bsc.load_beacon_state(slot, destination)
        self.LOGGER.debug({"msg": f"Downloaded Beacon State for {slot} to {destination}"})

    def _build_report(
            self, blockstamp: BlockStamp, beacon_state: BeaconState, withdrawal_credentials: HexBytes
    ) -> OracleReport:
        self.LOGGER.info({"msg": f"Building oracle report", "slot": blockstamp.slot_number})
        block_epoch = self._converter.get_epoch_by_slot(blockstamp.slot_number)
        balance, active, exited = 0, 0, 0
        for (idx, validator) in enumerate(beacon_state.validators):
            if validator.withdrawal_credentials != withdrawal_credentials:
                continue

            if validator.exit_epoch <= block_epoch:
                exited += 1
            if validator.activation_eligibility_epoch <= block_epoch:
                active += 1
            validator_balance = beacon_state.balances[idx]
            balance += validator_balance

        report = OracleReport(
            slot=blockstamp.slot_number,
            epoch=block_epoch,
            lidoWithdrawalCredentials=withdrawal_credentials,
            allLidoValidators=active,
            exitedValidators=exited,
            totalValueLocked=balance
        )
        self.LOGGER.debug({"msg": f"Built oracle report", "value": report.as_dict()})
        return report

    def build_proof(self, blockstamp: BlockStamp, beacon_state: BeaconState) -> OracleProof:
        self.LOGGER.info({"msg": f"Building oracle ZK-proof for slot {blockstamp.slot_number}"})
        balances_hash = Balances.get_hash_tree_root(beacon_state.balances)

        circuit_input = [
            {"array": list(beacon_state.balances)},
            {"vector": ProofProducer.as_field(balances_hash)},
            {"int": sum(beacon_state.balances)}
        ]
        proof = self._proof_producer.generate_proof(circuit_input)

        proof = OracleProof(
            # beaconBlockHash=blockstamp.block_hash,
            balances_hash=balances_hash,
            zk_proof=proof
        )
        self.LOGGER.debug({"msg": f"Built oracle ZK-proof", "value": proof.as_dict()})
        return proof

    def _submit_report(self, report: OracleReport, proof: OracleProof):
        if self.report_contract is None:
            self.LOGGER.error({"msg": "Cannot submit oracle report - ZKTVL contract is not configured"})
            return

        self.LOGGER.info(
            {"msg": "Submitting oracle report", "value": {"report": report.as_dict(), "proof": proof.as_dict_for_logging()}}
        )
        tx = self.report_contract.functions.submitReportData(report.as_tuple(), proof.as_tuple(), self.CONTRACT_VERSION)

        account = variables.ACCOUNT
        # self._web3.transaction.check_and_send_transaction(tx, account)
        params: TxParams = {
            "from": account.address,
            "maxFeePerGas": Wei(2 ** 31),
            "maxPriorityFeePerGas": Wei(2 ** 30),
            "nonce": self._web3.eth.get_transaction_count(account.address),
            "gas": constants.MAX_BLOCK_GAS_LIMIT - 1
        }
        receipt = self._web3.transaction._sign_and_send_transaction(tx, params, variables.ACCOUNT)
        self.LOGGER.debug({"msg": "Received tx_receipt", "value": receipt})
        print(f"Report submitted and accepted, gas used: {receipt.gasUsed}, transaction hash: {receipt.transactionHash.hex()}")


@dataclasses.dataclass
class ScriptArgs:
    slot: Optional[str] = None
    dry_run: bool = False
    # input_file: Optional[str] = None

# TODO: move to env?
PROOF_GENERATOR_BIN = os.path.join(
    # make a symlink to proof-generator in the script folder
    # cd this/script/folder && ln -s path/to/proof-generator proof-generator
    SCRIPT_FOLDER, "proof-generator",
)
# Note: _main is to indicate that this should not be imported directly, the "actual" main is in the __init__.py
def _main(args: ScriptArgs):
    web3, cc = initialize_chain_providers(check_chain_ids=False, lido_contracts_module=LidoZKLLVMMinimalContracts)
    beacon_state_client = BeaconStateClientModule(variables.BEACON_STATE_CLIENT_URI, web3)
    proof_producer = PrecomputedProofProducer(PRECOMPUTED_PROOF)
    # proof_producer = ProofGeneratorCLIProofProducer(
    #     PROOF_GENERATOR_BIN,
    #     os.path.join(SCRIPT_FOLDER, "circuit_statement.json")
    # )

    script = Script(web3, cc, beacon_state_client, proof_producer)

    last_finalized = get_last_finalized_slot(cc)
    target_slot = last_finalized.slot_number if args.slot is None or args.slot == 'finalized' else SlotNumber(
        int(args.slot)
    )
    blockstamp = get_blockstamp(cc, target_slot, last_finalized.slot_number)

    script.run(blockstamp, dry_run=args.dry_run)
