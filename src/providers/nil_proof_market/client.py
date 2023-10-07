import json
from typing import Optional, cast

from src import variables
from src.metrics.logging import logging
from src.metrics.prometheus.basic import PROOF_MARKET_REQUESTS_DURATION
from src.providers.http_provider import HTTPProvider
from src.providers.nil_proof_market.typings import (
    ProofMarketRequest, RequestKey, ProofKey, RequestStatus,
    ProofResponse, StatementKey
)
from src.utils.dataclass import list_of_dataclasses

logger = logging.getLogger(__name__)


class ProofMarketAPI(HTTPProvider):
    """
    API
    """
    PROMETHEUS_HISTOGRAM = PROOF_MARKET_REQUESTS_DURATION

    VERSION = 'v0_0'

    AUTH = "_open/auth"
    REQUEST = f"_db/market/{VERSION}/request/" + "{request_key}"
    PROOF = f"_db/market/{VERSION}/proof/" + "{proof_key}"

    def __init__(
            self,
            hosts: list[str],
            request_timeout: int,
            retry_total: int,
            retry_backoff_factor: int, ):
        super().__init__(hosts, request_timeout, retry_total, retry_backoff_factor)
        self._authenticate()

    def _authenticate(self):
        body = {"username": variables.PROOF_MARKET_USERNAME, "password": variables.PROOF_MARKET_PASSWORD}
        data, _ = self._post(self.AUTH, json=body)
        self.session.headers["Authorization"] = f'Bearer {data["jwt"]}'

    def submit_request(self, statement_key: StatementKey, payload: list[dict[str, any]], cost: float) -> ProofMarketRequest:
        """"""
        payload = {
            "statement_key": statement_key,
            "input": json.dumps(payload),
            "cost": cost,
        }
        data, _ = self._post(self.REQUEST.format(request_key=""), json=payload)
        return ProofMarketRequest.from_response(**cast(dict, data))

    def get_request(self, request_key: RequestKey) -> ProofMarketRequest:
        """"""
        data, _ = self._get(self.REQUEST.format(request_key=request_key))
        return ProofMarketRequest.from_response(**cast(dict, data))

    def _read_proof_key(self, request_key: RequestKey) -> Optional[ProofKey]:
        request = self.get_request(request_key)
        return request.proof_key
    def get_proof(self, proof_key: ProofKey) -> ProofResponse:
        data, _ = self._get(self.PROOF.format(proof_key=proof_key), query_params={'full': 'true'})
        return ProofResponse.from_response(**cast(dict, data))


# Quick self-check
if __name__ == "__main__":
    api = ProofMarketAPI(
        variables.PROOF_MARKET_URL,
        variables.HTTP_REQUEST_TIMEOUT_EXECUTION,
        variables.HTTP_REQUEST_RETRY_COUNT_CONSENSUS,
        variables.HTTP_REQUEST_SLEEP_BEFORE_RETRY_IN_SECONDS_CONSENSUS
    )

    request_data = api.get_request(RequestKey("119779267"))
    print(request_data)
    if request_data.status == RequestStatus.COMPLETED:
        proof_key = request_data.proof_key
        proof = api.get_proof(proof_key)
        # print(proof)
        print(proof.proof)
