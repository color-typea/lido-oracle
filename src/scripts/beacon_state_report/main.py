import os.path
from typing import Optional
import typed_argparse as tap
from dotenv import load_dotenv
from eth_account import Account

from src.metrics.logging import logging
logger = logging.getLogger()


class ArgumentParser(tap.TypedArgs):
    slot: Optional[str] = tap.arg('-s', default='finalized')
    env_file: Optional[str] = tap.arg('-e', default='mainnet')
    dry_run: Optional[bool] = tap.arg('-d', default=False)
    account_key: Optional[str] = tap.arg('-a', default=None)
    # input_file: Optional[str] = tap.arg("-i", default=None)


def setup_env(env_file: str):
    load_dotenv(env_file)
    from src import variables

    logger.debug({'msg': f'Initializing variables'})
    errors = variables.check_all_required_variables()
    variables.raise_from_errors(errors)


def main(args: ArgumentParser):
    if args.env_file is not None:
        setup_env(args.env_file)
    from src import variables
    if args.account_key:
        variables.ACCOUNT = Account.from_key(args.account_key)
    # this needs to be a local import - the moment `variables` is imported it reads from
    # env. `load_dotenv` must happen before that.
    from src.scripts.beacon_state_report.beacon_state_report import _main, ScriptArgs
    script_args = ScriptArgs(
        slot=args.slot,
        dry_run=args.dry_run
        # input_file=args.input_file,
    )
    _main(script_args)


if __name__ == '__main__':
    tap.Parser(ArgumentParser).bind(main).run()
