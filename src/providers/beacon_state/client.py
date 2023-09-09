from http import HTTPStatus
from typing import io, Optional, Sequence, Callable
from urllib.parse import urlparse

from src.metrics.logging import logging
from src.metrics.prometheus.basic import CL_REQUESTS_DURATION
from src.providers.common_typings import StateIdWithLiteral
from src.providers.consensus.typings import BeaconSpecResponse
from src.providers.http_provider import HTTPProvider, NotOkResponse

logger = logging.getLogger(__name__)


class BeaconStateClient(HTTPProvider):
    """
    API specifications can be found here
    https://ethereum.github.io/beacon-APIs/

    state_id
    State identifier. Can be one of: "head" (canonical head in node's view), "genesis", "finalized", "justified", <slot>, <hex encoded stateRoot with 0x prefix>.
    """
    PROMETHEUS_HISTOGRAM = CL_REQUESTS_DURATION

    API_GET_BEACON_STATE = '/eth/v2/debug/beacon/states/{}'
    API_GET_SPEC = 'eth/v1/config/spec'
    
    def load_beacon_state(self, state_id: StateIdWithLiteral, destination: io.BinaryIO):
        """
        Spec: https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockRoot

        There is no cache because this method is used to get finalized and head blocks.
        """
        self._load_stream(
            self.API_GET_BEACON_STATE,
            destination,
            path_params=(state_id,),
            headers={"Accept": "application/octet-stream"},
            force_raise=self.__raise_last_missed_slot_error,
        )

    def __raise_last_missed_slot_error(self, errors: list[Exception]) -> Exception | None:
        """
        Prioritize NotOkResponse before other exceptions (ConnectionError, TimeoutError).
        If status is 404 slot is missed and this should be handled correctly.
        """
        if len(errors) == len(self.hosts):
            for error in errors:
                if isinstance(error, NotOkResponse) and error.status == HTTPStatus.NOT_FOUND:
                    return error

        return None

    def _load_stream(
        self,
        endpoint: str,
        destination: io.BinaryIO,
        path_params: Optional[Sequence[str | int]] = None,
        query_params: Optional[dict] = None,
        headers: Optional[dict] = None,
        force_raise: Callable[..., Exception | None] = lambda _: None,
    ):
        """
        Get request with fallbacks
        Returns (data, meta) or raises exception

        force_raise - function that returns an Exception if it should be thrown immediately.
        Sometimes NotOk response from first provider is the response that we are expecting.
        """
        errors: list[Exception] = []

        for host in self.hosts:
            try:
                return self._load_stream_without_fallback(host, endpoint, destination, path_params, query_params, headers)
            except Exception as e:  # pylint: disable=W0703
                errors.append(e)

                # Check if exception should be raised immediately
                if to_force_raise := force_raise(errors):
                    raise to_force_raise from e

                logger.warning(
                    {
                        'msg': f'[{self.__class__.__name__}] Host [{urlparse(host).netloc}] responded with error',
                        'error': str(e),
                        'provider': urlparse(host).netloc,
                    }
                )

        # Raise error from last provider.
        raise errors[-1]

    def _load_stream_without_fallback(
        self,
        host: str,
        endpoint: str,
        destination: io.BinaryIO,
        path_params: Optional[Sequence[str | int]] = None,
        query_params: Optional[dict] = None,
        headers: Optional[dict] = None
    ):
        """
        Simple get request without fallbacks
        Returns (data, meta) or raises exception
        """
        complete_endpoint = endpoint.format(*path_params) if path_params else endpoint

        with self.PROMETHEUS_HISTOGRAM.time() as t:
            try:
                with self.session.get(
                    self._urljoin(host, complete_endpoint if path_params else endpoint),
                    params=query_params,
                    timeout=self.request_timeout,
                    headers=headers,
                ) as response:
                    t.labels(
                        endpoint=endpoint,
                        code=response.status_code,
                        domain=urlparse(host).netloc,
                    )

                    if response.status_code != HTTPStatus.OK:
                        response_fail_msg = f'Response from {complete_endpoint} [{response.status_code}] with text: "{str(response.text)}" returned.'
                        logger.debug({'msg': response_fail_msg})
                        raise NotOkResponse(response_fail_msg, status=response.status_code, text=response.text)

                    for chunk in response.iter_content(chunk_size=8192):
                        destination.write(chunk)

            except Exception as error:
                logger.error({'msg': str(error)})
                t.labels(
                    endpoint=endpoint,
                    code=0,
                    domain=urlparse(host).netloc,
                )
                raise error

    def _get_chain_id_with_provider(self, provider_index: int) -> int:
        data, _ = self._get_without_fallbacks(self.hosts[provider_index], self.API_GET_SPEC)
        if not isinstance(data, dict):
            raise ValueError("Expected mapping response from getSpec")
        return int(BeaconSpecResponse.from_response(**data).DEPOSIT_CHAIN_ID)
