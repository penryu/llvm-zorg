# COPYRIGHT LINE: FIXME

"""
dbsign.ansi
"""

from __future__ import print_function

import sys


def ANSI(color: str, msg: str) -> str:
    if sys.stdout.isatty():
        pre, post = _ANSI_CODES[color], _ANSI_CODES["clear"]
        msg = "{}{}{}".format(pre, msg, post)
    return msg


def OK(msg: str) -> str:
    return ANSI("green", msg)


def INFO(msg: str) -> str:
    return ANSI("blue", msg)


def WARN(msg: str) -> str:
    return ANSI("purple", msg)


def ERROR(msg: str) -> str:
    return ANSI("red", msg)


_ANSI_CODES = {
    "clear": "\033[0m",
    "blue": "\033[1;34m",
    "green": "\033[1;32m",
    "purple": "\033[1;35m",
    "red": "\033[1;31m",
}
