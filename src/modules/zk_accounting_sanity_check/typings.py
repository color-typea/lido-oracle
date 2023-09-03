import dataclasses

from hexbytes import HexBytes

from src.typings import BlockHash, SlotNumber, EpochNumber


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


@dataclasses.dataclass
class OracleReport(DataclassConvenience):
    data: OracleReportData
    proof: OracleProof