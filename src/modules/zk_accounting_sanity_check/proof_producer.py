import dataclasses
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
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
from src.providers.nil_proof_market.client import ProofMarketAPI
from src.providers.nil_proof_market.typings import (
    RequestKey, RequestStatus, ProofMarketRequest, StatementKey,
    ProofResponse, ProofKey
)
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
    sum: int


@dataclasses.dataclass
class PrivateInput:
    a: int
    b: int


@dataclasses.dataclass
class CircuitInput:
    public_input: PublicInput
    private_input: PrivateInput

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

    def _truncate(self, value, max_len: Optional[int] = None):
        # this is safe, if list is shorter, or if max_len is None it will just return the whole list
        return value[:max_len]

    def merkelize_pubkey(self, value):
        return ssz.get_hash_tree_root(value)

    def serialize_for_proof_generator(self):
        return [
            self.as_int(self.private_input.a),
            self.as_int(self.private_input.b),
            self.as_int(self.public_input.sum),
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


Errors = list[str]


@dataclasses.dataclass
class ProofRequestParameters:
    statement_key: StatementKey
    cost: float


@dataclasses.dataclass
class ProofMarketPollingParameters:
    poll_interval: int
    poll_timeout: int


class ProofMarketProofProducer(ProofProducer):
    LOGGER = logging.getLogger(__name__ + ".ProofMarketProofProducer")

    def __init__(
            self,
            proof_market_api: ProofMarketAPI,
            request_params: ProofRequestParameters,
            polling_param: ProofMarketPollingParameters
    ):
        self._proof_market_api = proof_market_api
        self.request_params = request_params
        self.polling_param = polling_param

    def proof_cost(self):
        return variables.PROOF_COST

    def generate_proof(self, circuit_input: CircuitInput) -> bytes:
        request_submission = self._submit_proof_request(circuit_input)
        proof_response = self._poll_for_proof(request_submission.key)
        return self._proof_from_hex_str(proof_response.proof)

    def _load_proof(self, request_key: RequestKey, proof_key: ProofKey) -> ProofResponse:
        self.LOGGER.info({"msg": f"Loading proof; request_key={request_key}, proof_key={proof_key}"})
        return self._proof_market_api.get_proof(proof_key)

    def _poll_for_proof(self, request_key: RequestKey) -> ProofResponse:
        start_time = time.time()
        self.LOGGER.info({"msg": f"Starting polling proof market for key={request_key}"})
        while True:
            elapsed = time.time() - start_time
            self.LOGGER.debug({"msg": f"t={elapsed:.2f}s; Polling proof market for key={request_key}."})
            request = self._proof_market_api.get_request(request_key)
            elapsed = time.time() - start_time
            self.LOGGER.info({"msg": f"t={elapsed:.2f}s; Request(key={request.key}) status -{request.status}"})

            if request.status == RequestStatus.COMPLETED:
                try:
                    self.LOGGER.info({"msg": f"Loading proof; request_key={request.key}, proof_key={request.proof_key}"})
                    return self._load_proof(request_key=request.key, proof_key=request.proof_key)
                except Exception as e:
                    elapsed = time.time() - start_time
                    self.LOGGER.warning(
                        {"msg": f"t={elapsed:.2f}s; Failed to load proof - will continue the wait loop\n{e}"}
                    )

            next_sleep = min(self.polling_param.poll_interval * 1.0, self.polling_param.poll_timeout - elapsed)
            if next_sleep <= 0:
                raise TimeoutError(f"Request was not fulfilled in {self.polling_param.poll_timeout}s")
            self.LOGGER.debug({"msg": f"Sleeping for {next_sleep:.2f}s"})
            time.sleep(next_sleep)

    def _submit_proof_request(self, circuit_input: CircuitInput) -> ProofMarketRequest:
        self.LOGGER.info(
            {"msg": f"Requesting poof for statement {self.request_params.statement_key} with cost {self.request_params.cost}"}
        )
        payload = circuit_input.serialize_for_proof_generator()
        self.LOGGER.debug(
            {"msg": "Request payload", "value": payload }
        )
        request = self._proof_market_api.submit_request(
            self.request_params.statement_key,
            payload,
            self.request_params.cost
        )
        self.LOGGER.info({"msg": f"Submitted request: key={request.key}"})
        return request


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
        errors = []
        if not variables.PROOF_MARKET_URL:
            errors.append(f"PROOF_MARKET_URL is not set")
        if not variables.PROOF_MARKET_CIRCUIT_STATEMENT_KEY:
            errors.append(f"PROOF_MARKET_CIRCUIT_STATEMENT_KEY is not set")
        if not variables.PROOF_COST:
            errors.append(f"PROOF_MARKET_URL is not set")
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

        return ProofMarketProofProducer(proof_market_api, request_params, polling_param), None
