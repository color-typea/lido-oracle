import dataclasses

from hexbytes import HexBytes

from src.typings import SlotNumber, EpochNumber


class DataclassConvenience:
    def as_tuple(self):
        return tuple(self.as_dict().values())

    def as_dict(self):
        return dataclasses.asdict(self)



@dataclasses.dataclass
class OracleReportData(DataclassConvenience):
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
    balances_hash: HexBytes
    validators_hash: HexBytes
    beacon_state_hash: HexBytes
    beacon_block_hash: HexBytes
    zk_proof: HexBytes

    def as_tuple(self):
        return (
            self.balances_hash,
            self.validators_hash,
            self.beacon_state_hash,
            self.beacon_block_hash,
            self.zk_proof,
        )

    def as_dict_for_logging(self):
        as_dict = dataclasses.asdict(self)
        as_dict['zk_proof'] = as_dict['zk_proof'].hex()
        as_dict['balances_hash'] = as_dict['balances_hash'].hex()
        as_dict['validators_hash'] = as_dict['validators_hash'].hex()
        as_dict['beacon_state_hash'] = as_dict['beacon_state_hash'].hex()
        as_dict['beacon_block_hash'] = as_dict['beacon_block_hash'].hex()

        del as_dict['zk_proof']
        # as_dict['zk_proof'] = as_dict['zk_proof'][:20] + b'\x01020304' + as_dict['zk_proof'][:-20]

        return as_dict


@dataclasses.dataclass
class OracleReport(DataclassConvenience):
    data: OracleReportData
    proof: OracleProof

    def as_tuple(self):
        return (self.data.as_tuple(), self.proof.as_tuple())