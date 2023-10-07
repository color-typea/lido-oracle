from enum import Enum
from typing import NewType, Optional

from dataclasses import dataclass

from eth_typing import HexStr

from src.utils.dataclass import FromResponse, Nested

StatementKey = NewType('StatementKey', str)
RequestKey = NewType('RequestKey', str)
ProposalKey = NewType('ProposalKey', str)
ProofKey = NewType('ProofKey', str)


class RequestStatus:
    CREATED = "created"
    PROCESSING = "processing"
    COMPLETED = 'completed'

@dataclass
class ProofMarketRequest(Nested, FromResponse):
    _key: RequestKey
    cost: int
    createdOn: int
    sender: str
    statement_key: StatementKey
    status: str  # Should be RequestStatus, but FromReponse does not handle enums properly
    updatedOn: int

    eval_time: Optional[int] = None
    generation_time: Optional[int] = None
    input: Optional[dict] = None
    matched_time: Optional[int] = None
    proof_key: Optional[ProofKey] = None
    proposal_key: Optional[ProposalKey] = None
    wait_period: Optional[int] = None

    # just syntactic sugar
    @property
    def key(self) -> RequestKey:
        return self._key

@dataclass
class ProofResponse(FromResponse):
    _key: ProofKey
    createdOn: int
    proof: HexStr
    sender: str
    statement_key: StatementKey
    updatedOn: int

    generation_time: Optional[int] = None
    proposal_key: Optional[ProposalKey] = None
    request_key: Optional[ProposalKey] = None

    # just syntactic sugar
    @property
    def key(self) -> ProofKey:
        return self._key
