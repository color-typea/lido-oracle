from typing import Optional, cast

from web3 import Web3 as _Web3


from src.web3py.extensions import (
    LidoContracts,
    TransactionUtils,
    ConsensusClientModule,
    KeysAPIClientModule,
    LidoValidatorsProvider, FallbackProviderModule,
)
from src.web3py.extensions.beacon_state import BeaconStateClientModule


class Web3(_Web3):
    lido_contracts: LidoContracts
    lido_validators: LidoValidatorsProvider
    transaction: TransactionUtils
    cc: ConsensusClientModule
    kac: Optional[KeysAPIClientModule]
    bsc: Optional[BeaconStateClientModule]

    def check_providers_chain_ids(self):
        chain_ids = {
            "Execution chain id": cast(FallbackProviderModule, self.provider).check_providers_consistency(),
            "Consensus chain id": self.cc.check_providers_consistency(),
        }

        if hasattr(self, "kac") and self.kac is not None:
            chain_ids["Execution chain id"] = self.kac.check_providers_consistency()

        if hasattr(self, "bsc") and self.bsc is not None:
            chain_ids["Beacon State Client chain id"] = self.bsc.check_providers_consistency()

        if len(set(chain_ids.values())) > 1:
            format_chain_ids = "\n".join(f"{label}: {chain_id}" for label, chain_id in chain_ids.items())
            raise ValueError(f'Different chain ids detected:\n{format_chain_ids}')
