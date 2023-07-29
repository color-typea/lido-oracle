from eth_typing import HexStr, HexAddress

from src import variables
from src.web3py.extensions import FallbackProviderModule, ConsensusClientModule
from src.web3py.typings import Web3

errors = variables.check_uri_required_variables()
variables.raise_from_errors(errors)

web3 = Web3(FallbackProviderModule(
        variables.EXECUTION_CLIENT_URI,
        request_kwargs={'timeout': variables.HTTP_REQUEST_TIMEOUT_EXECUTION}
))
cc = ConsensusClientModule(variables.CONSENSUS_CLIENT_URI, web3)

activated_at_epoch = 168427
# activated_at_epoch = 170250
SLOTS_IN_EPOCH = 32

staring_slot = (activated_at_epoch - 300) * SLOTS_IN_EPOCH
# ending_slot = 5448011 + 1
ending_slot = activated_at_epoch * SLOTS_IN_EPOCH

missing_keys=[
    "0x815dae823afade85283358bdc8af82c76298b1c0229a0387e98de1888537b878c7a0a3fa9ec6942bea0f2ffac6773483",
    "0x97e19d8b5efd6584ac0696d00d39f602669ab75458c542f94f062f1e422672de399d20384ec51b945e27a0dadcc4960f",
    "0x843690fc91061d2bf4b1f8b428bbf1be4cd654de5394733ac16ec5ab817f07c522020aaa8437c6622a5a75a53dfd680e",
]

def read_deposit_event_pubkey(event_data):
    start, end = 386, 482
    return "0x" + event_data.hex()[start:end]

class Topics:
    DepositEvent = HexStr('0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5')
    DepositedSigningKeysCountChanged = HexStr("0x24eb1c9e765ba41accf9437300ea91ece5ed3f897ec3cdee0e9debd7fe309b78")


# start_block, end_block = cc.get_block_root(SlotNumber(staring_slot)), cc.get_block_root(SlotNumber(ending_slot))

print(f"Search in range {staring_slot}, {ending_slot}")

start_block, end_block = 8802385, 8809884

SLIDE_WINDOW = 500

if start_block is not None and end_block is not None:
    for start_idx in range(start_block, end_block, SLIDE_WINDOW):
        logs = web3.eth.get_logs({
            # 'address': HexAddress('0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b'),
            'topics': [
                Topics.DepositEvent,
                # Topics.DepositedSigningKeysCountChanged
            ],
            'fromBlock': start_idx,
            'toBlock': start_idx + SLIDE_WINDOW
        })
        for log in logs:
            pubkey = read_deposit_event_pubkey(log["data"])
            if pubkey.lower() in missing_keys:
                print("Found tx!", pubkey, log["transactionHash"].hex(), log["blockNumber"])