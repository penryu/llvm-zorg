#!/usr/bin/env python3

import os
import sys

from argparse import ArgumentParser

import commands
import logger
import security

from commands import CFG


log = logger.get_logger(CFG["executable"])


def make_parser() -> ArgumentParser:
    parser = ArgumentParser(prog=CFG["executable"], add_help=False)
    parser.set_defaults(func=lambda: commands.cmd_help(parser))
    parser.add_argument(
        "--debug",
        "-d",
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="be more verbose",
    )
    parser.add_argument("--quiet", "-q", action="count", default=0, help="be quieter")
    parser.add_argument(
        "--unsafe", action="store_true", help="permit unsafe operations"
    )
    subparsers = parser.add_subparsers(help="Subcommands")

    parser_help = subparsers.add_parser("help", help="Display usage info")
    parser_help.set_defaults(func=lambda: commands.cmd_help(parser))

    parser_check = subparsers.add_parser(
        "check", help="Validate current system settings"
    )
    parser_check.set_defaults(func=commands.cmd_check)

    parser_clean = subparsers.add_parser("clean", help="Remove identity and keychain")
    parser_clean.set_defaults(func=commands.cmd_clean)

    parser_import = subparsers.add_parser(
        "import", help="Import and trust new identity from .P12 file"
    )
    parser_import.set_defaults(func=commands.cmd_import)
    parser_import.add_argument(
        "id_file", metavar="P12_FILE", help="Identity in .p12 format"
    )

    parser_setup = subparsers.add_parser(
        "setup", help="Initialize keychain and privilege settings"
    )
    parser_setup.set_defaults(func=commands.cmd_setup)

    parser_unlock = subparsers.add_parser(
        "prep", help="Unlock keychain and verify identity is valid"
    )
    parser_unlock.set_defaults(func=commands.cmd_prep)

    parser_remove = subparsers.add_parser(
        "remove", help="Remove the installed identity"
    )
    parser_remove.set_defaults(func=commands.cmd_remove)

    parser_lint = subparsers.add_parser("lint", help="Lint the program source code")
    parser_lint.set_defaults(func=commands.cmd_lint)

    parser_test = subparsers.add_parser("test", help="Test the program")
    parser_test.set_defaults(func=commands.cmd_test)

    return parser


def main(main_args: list[str]) -> int:
    parser = make_parser()
    args = parser.parse_args(main_args)

    if args.unsafe:
        os.environ[security.UNSAFE_FLAG] = "YES"

    # Logging setup
    level = logger.BASE_LOGLEVEL + (args.quiet - args.debug) * 10
    logger.set_level(logger.normalize(level))

    CFG["debug"] = args.debug > 0
    CFG["keydb"] = "{}/Library/Keychains/{}.{}".format(
        os.environ["HOME"], CFG["keynick"], security.derive_keychain_extension()
    )
    if hasattr(args, "id_file"):
        CFG["id_file"] = args.id_file

    log.debug("Command line parameters: %s", sys.argv)
    log.debug("Arguments to main: %s", main_args)
    log.debug("Parsed args: %s", args)
    log.debug("Configuration: %s", CFG)

    return args.func()


if __name__ == "__main__":
    return_code: int = main(sys.argv[1:])
    sys.exit(return_code)
