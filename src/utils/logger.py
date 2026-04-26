"""
Logger — structured logging with Rich handler.
"""

import logging
from rich.logging import RichHandler


def setup_logger(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                rich_tracebacks=True,
                show_path=verbose,
                markup=True,
            )
        ],
    )
    logger = logging.getLogger("threatlens")
    logger.setLevel(level)
    return logger
