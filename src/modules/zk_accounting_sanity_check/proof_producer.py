import json
import logging
import os
import subprocess
import sys
import tempfile
from typing import Any, List, Dict
from abc import ABCMeta, abstractmethod

FieldType = (str, str)

class ProofProducer(metaclass=ABCMeta):
    @abstractmethod
    def generate_proof(self, public_input: List[Dict[str, Any]]) -> bytes:
        pass

    @classmethod
    def as_field(cls, value: bytes) -> FieldType:
        low = int.from_bytes(value[:16], 'little', signed=False)
        high = int.from_bytes(value[16:], 'little', signed=False)
        return str(low), str(high)

class PrecomputedProofProducer(ProofProducer):
    LOGGER = logging.getLogger(__name__ + ".PrecomputedProofProducer")
    def __init__(self, proof_file: str):
        self.proof_file = proof_file

    def generate_proof(self, public_input: List[Dict[str, Any]])  -> bytes:
        self.LOGGER.info({"msg": f"Passed input {public_input}"})
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
        return [self.proof_producer_bin] + self._flatten_named_args({
            "--proof_out": output_file,
            "--circuit_input": self.circuit_statement_file,
            "--public_input": public_input_file,
        })

    def _stub_public_input(self):
        return  [
            {"vector": ["326522724692461750427768532537390503835", "89059515727727869117346995944635890507"]},
            {"vector": ["291547819587797372485177713898460727720", "194782098816759892662980765881849306481"]}
        ]

    def generate_proof(self, public_input: List[Dict[str, Any]])  -> bytes:
        """
        Invokes proof-generator cli with corresponding arguments
        and waits for proof to be written
        """
        self.LOGGER.info({"msg": "Invoking proof producer"})
        output_file_name = os.path.join(tempfile.gettempdir(), "proof.bin")
        public_input_file = tempfile.NamedTemporaryFile("w", prefix="public_input", delete=False)
        try:
            # json.dump(public_input, public_input_file)
            json.dump(self._stub_public_input(), public_input_file)
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