import asyncio
import dataclasses
import json
import logging
import math
import os
import subprocess
import sys
import tempfile
import time
from enum import StrEnum
from functools import cached_property
from typing import List, Callable, TypeVar, Iterable, Optional, Any
from abc import ABCMeta, abstractmethod, ABC

import ssz.utils
from eth_typing import Hash32
from hexbytes import HexBytes
from ssz.hash import hash_eth2

from src import variables
from src.modules.zk_accounting_sanity_check.eth_consensus_layer_ssz import Validators, Balances, Validator
from src.modules.zk_accounting_sanity_check.typings import OracleReportData
from src.providers.nil_proof_market.client import ProofMarketAPI
from src.providers.nil_proof_market.typings import (
    RequestKey, RequestStatus, ProofMarketRequest, StatementKey,
    ProofResponse
)
from src.typings import EpochNumber, SlotNumber


class ProofProducerMode(StrEnum):
    PRECOMPUTED = 'precomputed'
    COMMANDLINE = 'commandline'
    PROOF_MARKET = 'proof_market'
    PROOF_MARKET_RECURSIVE = 'proof_market_recursive'


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


class InputBase(ABC):
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
    def as_field(cls, value: bytes) -> HashType:
        assert len(value) <= 16, f"Serializing as field only support values shorter than 16 bytes, {len(value)} given"
        return {"field": str(int.from_bytes(value, 'little', signed=False))}

    @classmethod
    def as_hash(cls, value: bytes) -> HashType:
        assert len(value) <= 32, f"Serializing as hash only support values shorter than 32 bytes, {len(value)} given"
        return {"vector": [cls.as_field(value[:16]), cls.as_field(value[16:])]}

    @classmethod
    def as_struct(clscls, value: T, mapper: Callable[[T], List[Any]]):
        return {"struct": [mapper(value)]}

    @abstractmethod
    def serialize_for_proof_generator(self):
        pass


class MergeCircuitInput(InputBase):
    def __init__(self, left: HexBytes, right: HexBytes):
        self._left = left
        self._right = right

    def _slice_bytes_into_field_chunks(self, value: HexBytes):
        field_size_in_bytes = 16
        chunks_count = math.ceil(len(value) // field_size_in_bytes)
        chunks = [
            value[idx:idx + field_size_in_bytes]
            for idx in range(chunks_count)
        ]
        last_chunk = chunks[-1]
        padding = field_size_in_bytes - len(last_chunk)
        if padding > 0:
            chunks[-1] = chunks[-1] + b'\x00' * padding

        return chunks

    def serialize_for_proof_generator(self):
        # TODO: serialize for merge circuit - this is a guess
        return [
            self.as_array(self._slice_bytes_into_field_chunks(self._left), self.as_field),
            self.as_array(self._slice_bytes_into_field_chunks(self._right), self.as_field)
        ]


@dataclasses.dataclass
class CircuitInput(InputBase):
    public_input: PublicInput
    private_input: PrivateInput
    report_data: OracleReportData

    # this is temporary means to limit the amount of data we're sending to the prover
    TRUNCATE_VALIDATORS = 16

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
            self.as_array(
                self.validator_field_for_merkleization(lambda validator: hash_eth2(validator.pubkey + b'\x00' * 16)),
                self.as_hash
            ),
            self.as_array(
                self.validator_field_for_merkleization(lambda validator: validator.withdrawal_credentials), self.as_hash
            ),
            self.as_array(
                self.validator_field_for_merkleization(lambda validator: validator.effective_balance), self.as_int
            ),
            self.as_array(
                self.validator_field_for_merkleization(lambda validator: 1 if validator.slashed else 0), self.as_int
            ),
            self.as_array(
                self.validator_field_for_merkleization(lambda validator: validator.activation_eligibility_epoch),
                self.as_int
            ),
            self.as_array(
                self.validator_field_for_merkleization(lambda validator: validator.activation_epoch), self.as_int
            ),
            self.as_array(self.validator_field_for_merkleization(lambda validator: validator.exit_epoch), self.as_int),
            self.as_array(
                self.validator_field_for_merkleization(lambda validator: validator.withdrawable_epoch), self.as_int
            ),

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

    def _proof_from_hex_str(self, proof_hex: str) -> bytes:
        return bytes.fromhex(proof_hex[2:])


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
            proof = self._proof_from_hex_str(proof_bin_hex.read())

        return proof


@dataclasses.dataclass
class ProofRequestParameters:
    statement_key: StatementKey
    cost: float


@dataclasses.dataclass
class RecursiveProofRequestParameters:
    statement_key: StatementKey
    merge_statement_key: StatementKey
    subtasks_labels: List[str]
    cost: float


@dataclasses.dataclass
class ProofMarketPollingParameters:
    poll_interval: int
    poll_timeout: int


class ProofMarketProofProducerBase(ABC, ProofProducer):
    def __init__(
            self,
            proof_market_api: ProofMarketAPI,
            polling_param: ProofMarketPollingParameters
    ):
        self._proof_market_api = proof_market_api
        self._polling_param = polling_param

    @property
    @abstractmethod
    def logger(self) -> logging.Logger:
        pass

    @property
    def proof_cost(self):
        return variables.PROOF_COST

    async def _submit_request(
            self, statement_key: StatementKey, payload: list[dict[str, any]], subkey: Optional[str] = None
    ):
        self.logger.debug({"msg": "Request payload", "value": payload})
        request = await self._proof_market_api.submit_request_async(
            statement_key,
            payload,
            self.proof_cost,
            subkey=subkey
        )
        self.logger.info({"msg": f"Submitted request: key={request.key}"})
        return request

    async def _poll_for_proof(self, request_key: RequestKey) -> ProofResponse:
        start_time = time.time()
        self.logger.info({"msg": f"Starting polling proof market for key={request_key}"})
        while True:
            elapsed = time.time() - start_time
            self.logger.debug({"msg": f"t={elapsed:.2f}s; Polling proof market for key={request_key}."})
            request = await self._proof_market_api.get_request_async(request_key)
            elapsed = time.time() - start_time
            self.logger.info({"msg": f"t={elapsed:.2f}s; Request(key={request.key}) status -{request.status}"})

            if request.status == RequestStatus.COMPLETED:
                try:
                    self.logger.info(
                        {"msg": f"Loading proof; request_key={request.key}, proof_key={request.proof_key}"}
                    )
                    return await self._proof_market_api.get_proof_async(request.proof_key)
                except Exception as e:
                    elapsed = time.time() - start_time
                    self.logger.warning(
                        {"msg": f"t={elapsed:.2f}s; Failed to load proof - will continue the wait loop\n{e}"}
                    )

            next_sleep = min(self._polling_param.poll_interval * 1.0, self._polling_param.poll_timeout - elapsed)
            if next_sleep <= 0:
                raise TimeoutError(f"Request was not fulfilled in {self._polling_param.poll_timeout}s")
            self.logger.debug({"msg": f"Sleeping for {next_sleep:.2f}s"})
            await asyncio.sleep(next_sleep)


class ProofMarketProofProducer(ProofMarketProofProducerBase):
    def __init__(
            self, proof_market_api: ProofMarketAPI, polling_param: ProofMarketPollingParameters,
            request_params: ProofRequestParameters
    ):
        super().__init__(proof_market_api, polling_param)
        self.request_params = request_params

    @cached_property
    def logger(self) -> logging.Logger:
        return logging.getLogger(f"{__name__} + {self.__class__.__name__}")

    def generate_proof(self, circuit_input: CircuitInput) -> bytes:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self._generate_proof(circuit_input))

    async def _generate_proof(self, circuit_input: CircuitInput) -> bytes:
        request_submission = await self._submit_proof_request(circuit_input)
        proof_response = await self._poll_for_proof(request_submission.key)
        return self._proof_from_hex_str(proof_response.proof)

    async def _submit_proof_request(self, circuit_input: CircuitInput) -> ProofMarketRequest:
        self.logger.info(
            {
                "msg": f"Requesting poof for statement {self.request_params.statement_key} with cost "
                       f"{self.request_params.cost}"}
        )
        payload = circuit_input.serialize_for_proof_generator()
        self.logger.debug(
            {"msg": "Request payload", "value": payload}
        )
        return await self._submit_request(
            self.request_params.statement_key,
            payload,
        )


class RecursiveProofMarketProofProducer(ProofMarketProofProducerBase):
    LOGGER = logging.getLogger(__name__ + ".RecursiveProofMarketProofProducer")

    def __init__(
            self,
            proof_market_api: ProofMarketAPI,
            request_params: RecursiveProofRequestParameters,
            polling_param: ProofMarketPollingParameters
    ):
        super().__init__(proof_market_api, polling_param)
        self.request_params = request_params
        assert math.log(
            len(request_params.subtasks_labels), 2
        ).is_integer(), "Number of subtasks is not a power of two - merging won't work"

    @cached_property
    def logger(self) -> logging.Logger:
        return logging.getLogger(f"{__name__} + {self.__class__.__name__}")

    def generate_proof(self, circuit_input: CircuitInput) -> bytes:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self._generate_proof(circuit_input))

    async def _generate_proof(self, circuit_input: CircuitInput) -> bytes:
        requests = list(
            await asyncio.gather(*[
                self._submit_leaf(circuit_input, subtask)
                for subtask in self.request_params.subtasks_labels
            ])
        )
        total_layers = math.log2(len(self.request_params.subtasks_labels))

        layer = 0
        while len(requests) > 1:
            self.LOGGER.info({"msg": f"Layer {layer:03}/{total_layers} starting"})
            requests = await self._process_layer(layer, requests)
            self.LOGGER.info({"msg": f"Layer {layer:03}/{total_layers} done"})
            layer += 1

        proof_response = await self._poll_for_proof(requests[0])
        return self._proof_from_hex_str(proof_response.proof)

    async def _process_layer(self, layer: int, requests: list[ProofMarketRequest]) -> list[ProofMarketRequest]:
        responses = await asyncio.gather(*[
            self._poll_for_proof(request.key)
            for request in requests
        ])
        assert len(responses) % 2 == 0, f"Odd number of responses at layer {layer}"
        result = await asyncio.gather(*[
            self._submit_merge(responses[idx], responses[idx + 1])
            for idx in range(math.ceil(len(responses) / 2))
        ])
        return list(result)

    async def _submit_leaf(self, circuit_input: CircuitInput, subkey: Optional[str] = None) -> ProofMarketRequest:
        self.LOGGER.info({
            "msg": f"Requesting poof for statement {self.request_params.statement_key}(subkey: {subkey}) with "
            f"cost {self.request_params.cost}"
        })
        payload = circuit_input.serialize_for_proof_generator()
        self.LOGGER.debug({"msg": "Request payload", "value": payload})
        return await self._submit_request(
            self.request_params.statement_key,
            payload,
            subkey
        )

    async def _submit_merge(self, left: ProofResponse, right: ProofResponse):
        self.LOGGER.info({
            "msg": f"Requesting merging proofs for statement {self.request_params.statement_key} with cost "
                   f"{self.request_params.cost}"
        })
        merge_payload = MergeCircuitInput(HexBytes(left.proof), HexBytes(right.proof))
        payload = merge_payload.serialize_for_proof_generator()
        return await self._submit_request(
            self.request_params.statement_key,
            payload,
        )


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
        elif mode == ProofProducerMode.PROOF_MARKET_RECURSIVE:
            factory = cls._proof_market_recursive
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
        errors = []
        if not variables.PROOF_MARKET_URL:
            errors.append(f"PROOF_MARKET_URL is not set")
        if not variables.PROOF_MARKET_CIRCUIT_STATEMENT_KEY:
            errors.append(f"PROOF_MARKET_CIRCUIT_STATEMENT_KEY is not set")
        if not variables.PROOF_COST:
            errors.append(f"PROOF_MARKET_URL is not set")

        if errors:
            return None, errors

        proof_market_api = ProofMarketAPI(
            variables.PROOF_MARKET_URL,
            variables.HTTP_REQUEST_TIMEOUT_EXECUTION,
            variables.HTTP_REQUEST_RETRY_COUNT_CONSENSUS,
            variables.HTTP_REQUEST_SLEEP_BEFORE_RETRY_IN_SECONDS_CONSENSUS
        )
        request_params = ProofRequestParameters(
            variables.PROOF_MARKET_CIRCUIT_STATEMENT_KEY,
            variables.PROOF_COST
        )
        polling_param = ProofMarketPollingParameters(
            variables.PROOF_MARKET_POLLING_PERIOD,
            variables.PROOF_MARKET_PROOF_GENERATION_TIMEOUT
        )

        return ProofMarketProofProducer(proof_market_api, polling_param, request_params), None

    @classmethod
    def _proof_market_recursive(cls) -> (ProofProducer, Errors):
        errors = []
        if not variables.PROOF_MARKET_URL:
            errors.append(f"PROOF_MARKET_URL is not set")
        if not variables.PROOF_MARKET_CIRCUIT_STATEMENT_KEY:
            errors.append(f"PROOF_MARKET_CIRCUIT_STATEMENT_KEY is not set")
        if not variables.PROOF_MARKET_MERGE_STATEMENT_KEY:
            errors.append(f"PROOF_MARKET_MERGE_STATEMENT_KEY is not set")
        if not variables.PROOF_COST:
            errors.append(f"PROOF_MARKET_URL is not set")
        if not variables.PROOF_MARKET_CIRCUIT_SUBTASKS_COUNT:
            errors.append(f"PROOF_MARKET_CIRCUIT_SUBTASKS_COUNT is not set")

        if errors:
            return None, errors

        proof_market_api = ProofMarketAPI(
            variables.PROOF_MARKET_URL,
            variables.HTTP_REQUEST_TIMEOUT_EXECUTION,
            variables.HTTP_REQUEST_RETRY_COUNT_CONSENSUS,
            variables.HTTP_REQUEST_SLEEP_BEFORE_RETRY_IN_SECONDS_CONSENSUS
        )
        request_params = RecursiveProofRequestParameters(
            variables.PROOF_MARKET_CIRCUIT_STATEMENT_KEY,
            variables.PROOF_MARKET_MERGE_STATEMENT_KEY,
            [f"{idx}" for idx in range(variables.PROOF_MARKET_CIRCUIT_SUBTASKS_COUNT)],
            variables.PROOF_COST
        )
        polling_param = ProofMarketPollingParameters(
            variables.PROOF_MARKET_POLLING_PERIOD,
            variables.PROOF_MARKET_PROOF_GENERATION_TIMEOUT
        )

        return RecursiveProofMarketProofProducer(proof_market_api, request_params, polling_param), None
