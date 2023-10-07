import dataclasses
import json
import logging
import os
import subprocess
import sys
import tempfile
from enum import StrEnum
from typing import List, Callable, TypeVar, Iterable, Optional
from abc import ABCMeta, abstractmethod

import ssz.utils
from eth_typing import Hash32
from hexbytes import HexBytes
from ssz.hash import hash_eth2

from src import variables
from src.modules.zk_accounting_sanity_check.eth_consensus_layer_ssz import Validators, Balances, Validator
from src.modules.zk_accounting_sanity_check.typings import OracleReportData
from src.typings import EpochNumber, SlotNumber


class ProofProducerMode(StrEnum):
    PRECOMPUTED = 'precomputed'
    COMMANDLINE = 'commandline'
    PROOF_MARKET = 'proof_market'


HashType = (str, str)
T = TypeVar("T")
TOut = TypeVar("TOut")


@dataclasses.dataclass
class PublicInput:
    lido_withdrawal_credentials: Hash32
    beacon_state_hash: Hash32
    beacon_block_hash: Hash32
    slot: SlotNumber
    epoch: EpochNumber


@dataclasses.dataclass
class PrivateInput:
    validators: Validators
    balances: Balances
    balances_hash: Hash32
    validators_hash: Hash32
    balances_hash_inclusion_proof: List[HexBytes]
    validators_hash_inclusion_proof: List[HexBytes]
    beacon_block_fields: List[HexBytes]


@dataclasses.dataclass
class CircuitInput:
    public_input: PublicInput
    private_input: PrivateInput
    report_data: OracleReportData

    # this is temporary means to limit the amount of data we're sending to the prover
    TRUNCATE_VALIDATORS = 16

    @classmethod
    def as_int(cls, val):
        return {"int": val}

    @classmethod
    def as_array(cls, val: Iterable[T], mapper: Callable[[T], TOut]):
        return cls._iterable("array", val, mapper)

    @classmethod
    def as_vector(cls, val, mapper: Callable[[T], TOut]):
        return cls._iterable("verctor", val, mapper)

    @classmethod
    def _iterable(cls, type_label, value, mapper: Callable[[T], TOut]):
        mapped_values = [mapper(item) for item in value]
        return {type_label: mapped_values}

    @classmethod
    def as_hash(cls, value: bytes) -> HashType:
        assert len(value) <= 32, f"Serializing as hash only support values shorter than 32 bytes, {len(value)} given"
        low = int.from_bytes(value[:16], 'little', signed=False)
        high = int.from_bytes(value[16:], 'little', signed=False)
        return {"vector": [{"field": str(low)}, {"field": str(high)}]}

    @property
    def validators(self):
        return self._truncate(self.private_input.validators, self.TRUNCATE_VALIDATORS)

    @property
    def balances(self):
        return self._truncate(self.private_input.balances, self.TRUNCATE_VALIDATORS)


    def _truncate(self, value, max_len: Optional[int] = None):
        # this is safe, if list is shorter, or if max_len is None it will just return the whole list
        return value[:max_len]


    def validator_field_for_merkleization(self, extractor: Callable[[Validator], T]) -> List[T]:
        return [extractor(validator) for validator in self.validators]

    def merkelize_pubkey(self, value):
        return ssz.get_hash_tree_root(value)

    def serialize_for_proof_generator(self):
        return [
            self.as_int(len(self.validators)),
            self.as_array(self.balances, self.as_int),
            # Validator parts
            self.as_array(self.validator_field_for_merkleization(lambda validator: hash_eth2(validator.pubkey+b'\x00'*16)), self.as_hash),
            self.as_array(self.validator_field_for_merkleization(lambda validator: validator.withdrawal_credentials), self.as_hash),
            self.as_array(self.validator_field_for_merkleization(lambda validator: validator.effective_balance), self.as_int),
            self.as_array(self.validator_field_for_merkleization(lambda validator: 1 if validator.slashed else 0), self.as_int),
            self.as_array(self.validator_field_for_merkleization(lambda validator: validator.activation_eligibility_epoch), self.as_int),
            self.as_array(self.validator_field_for_merkleization(lambda validator: validator.activation_epoch), self.as_int),
            self.as_array(self.validator_field_for_merkleization(lambda validator: validator.exit_epoch), self.as_int),
            self.as_array(self.validator_field_for_merkleization(lambda validator: validator.withdrawable_epoch), self.as_int),

            # "Configuration parameters"
            self.as_hash(self.public_input.lido_withdrawal_credentials),
            self.as_int(self.public_input.slot),
            self.as_int(self.public_input.epoch),

            # Report values
            self.as_int(self.report_data.totalValueLocked),
            self.as_int(self.report_data.allLidoValidators),
            self.as_int(self.report_data.exitedValidators),

            # Expected hashes
            self.as_hash(self.private_input.balances_hash),
            self.as_hash(self.private_input.validators_hash),
            self.as_hash(HexBytes(self.public_input.beacon_state_hash)),
            self.as_hash(HexBytes(self.public_input.beacon_block_hash)),

            # Inclusion proofs
            self.as_array(self.private_input.balances_hash_inclusion_proof, self.as_hash),
            self.as_array(self.private_input.validators_hash_inclusion_proof, self.as_hash),

            # Beacon block fields
            self.as_array(self.private_input.beacon_block_fields, self.as_hash),
        ]


class ProofProducer(metaclass=ABCMeta):
    @abstractmethod
    def generate_proof(self, circuit_input: CircuitInput) -> bytes:
        pass


class PrecomputedProofProducer(ProofProducer):
    LOGGER = logging.getLogger(__name__ + ".PrecomputedProofProducer")

    def __init__(self, proof_file: str):
        self.proof_file = proof_file

    def generate_proof(self, proof_input: CircuitInput) -> bytes:
        self.LOGGER.info({"msg": f"Passed input {proof_input}"})
        with open(self.proof_file, "r") as proof_bin_hex:
            proof_hex = proof_bin_hex.read()
            proof = bytes.fromhex(proof_hex[2:])

        return proof


class ProofGeneratorCLIProofProducer(ProofProducer):
    LOGGER = logging.getLogger(__name__ + ".ProofGeneratorCLIProofProducer")

    def __init__(self, proof_producer_bin: str, circuit_statement_file: str):
        self.proof_producer_bin = proof_producer_bin
        self.circuit_statement_file = circuit_statement_file

    def _flatten_named_args(self, named_args: dict[str, str]) -> List[str]:
        return [
            item
            for key, value in named_args.items()
            for item in (key, value)
        ]

    def _gen_run_args(self, public_input_file: str, output_file: str):
        return [self.proof_producer_bin] + self._flatten_named_args(
            {
                "--proof_out": output_file,
                "--circuit_input": self.circuit_statement_file,
                "--public_input": public_input_file,
            }
        )

    def generate_proof(self, proof_input: CircuitInput) -> bytes:
        """
        Invokes proof-generator cli with corresponding arguments
        and waits for proof to be written
        """
        self.LOGGER.info({"msg": "Invoking proof producer"})
        output_file_name = os.path.join(tempfile.gettempdir(), "proof.bin")
        public_input_file = tempfile.NamedTemporaryFile("w", prefix="public_input", delete=False)
        try:
            # json.dump(public_input, public_input_file)
            json.dump(proof_input.serialize_for_proof_generator(), public_input_file)
            public_input_file.close()
            args = self._gen_run_args(public_input_file.name, output_file_name)
            cmd = " ".join(args)
            self.LOGGER.info({"msg": f"Executing proof generator command {cmd}"})
            process = subprocess.run(args, stdout=sys.stdout, stderr=sys.stderr)
            if process.returncode != 0:
                raise Exception(f"Failed to run proof generator - retcode {process.returncode}")
        finally:
            os.remove(public_input_file.name)

        with open(output_file_name, "r") as proof_bin_hex:
            proof_hex = proof_bin_hex.read()
            proof = bytes.fromhex(proof_hex[2:])

        return proof


Errors = list[str]


class ProofProducerFactory:
    @classmethod
    def create(cls) -> ProofProducer:
        mode = variables.PROOF_PRODUCER_MODE
        if mode == ProofProducerMode.PRECOMPUTED:
            factory = cls._precomputed
        elif mode == ProofProducerMode.COMMANDLINE:
            factory = cls._cmdline
        elif mode == ProofProducerMode.PROOF_MARKET:
            factory = cls._proof_market
        else:
            raise ValueError(f"Proof producer mode {mode} is unsupported - please check your .env file")

        producer, errors = factory()

        if errors:
            errors_str = "\n".join(errors)
            raise ValueError(
                f"Encountered errors creating a ProofProducer with PROOF_PRODUCER_MODE={mode}\n{errors_str}"
            )

        return producer

    @classmethod
    def _check_file_exists(cls, file_path):
        return file_path and os.path.exists(file_path) and os.path.isfile(file_path)

    @classmethod
    def _precomputed(cls) -> (ProofProducer, Errors):
        if not cls._check_file_exists(variables.PROOF_FILE):
            return None, ["PROOF_FILE must be a path to a file"]
        return PrecomputedProofProducer(variables.PROOF_FILE), None

    @classmethod
    def _cmdline(cls) -> (ProofProducer, Errors):
        errors = []
        if not cls._check_file_exists(variables.PROOF_GENERATOR_BIN):
            errors.append(f"PROOF_GENERATOR_BIN must be a path to a file")
        if not cls._check_file_exists(variables.PROOF_CIRCUIT_STATEMENT):
            errors.append(f"PROOF_CIRCUIT_STATEMENT must be a path to a file")

        if errors:
            return None, errors

        return ProofGeneratorCLIProofProducer(variables.PROOF_GENERATOR_BIN, variables.PROOF_CIRCUIT_STATEMENT), None

    @classmethod
    def _proof_market(cls) -> (ProofProducer, Errors):
        raise NotImplementedError("ZKLLVM Proof market integration is not yet implemented")
