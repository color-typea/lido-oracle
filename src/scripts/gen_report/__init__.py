from typing import Optional

from dotenv import load_dotenv

from src.scripts.utils import Chain
from src.metrics.logging import logging
from src.typings import OracleModule
import typed_argparse as tap

logger = logging.getLogger()


class ArgumentParser(tap.TypedArgs):
    module: OracleModule = tap.arg("-m", positional=True)
    slot: Optional[int] = tap.arg('-s', default=None)
    chain: Chain = tap.arg("-c", default=Chain.MAINNET)


def setup_env(chain: Chain):
    logger.debug({'msg': f'Using {chain} config.'})
    load_dotenv(f".env.{chain.value}")
    from src import variables

    logger.debug({'msg': f'Initializing variables'})
    errors = variables.check_all_required_variables()
    variables.raise_from_errors(errors)


def main(args: ArgumentParser):
    setup_env(args.chain)
    # this needs to be a local import - the moment `variables` is imported it reads from
    # env. `load_dotenv` must happen before that.
    from generate_report import _main
    _main(args.module, args.slot)


if __name__ == '__main__':
    tap.Parser(ArgumentParser).bind(main).run()
