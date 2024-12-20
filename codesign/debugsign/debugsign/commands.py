# COPYRIGHT LINE: FIXME

"""
dbsign.commands
"""

from __future__ import print_function

import os
import sys

from argparse import ArgumentParser
from logging import Logger

from result import Result

import logger
import security
import shell

from ansi import ERROR, INFO, OK, WARN

#
# Globals and configurables
#

OVERVIEW_TEXT: str = """\

{1}
OVERVIEW:

    To configure code signing on a new system, do the following (in order):

        {0} setup
        {0} import P12_FILE     # MUST BE DONE FROM GUI CONSOLE!

    To verify the configuration:

        {0} check               # Not foolproof, but catches most issues

    To enable access to the identity for code signing (eg, from Jenkins job):

        {0} prep

    To replace the configured identity with a new one:

        {0} remove              # Removes the whole keychain!
        {0} import NEW_P12      # Must be done from GUI console!

    Note that this script currently assumes the following:

      * The identity's common name will be "lldb_codesign"
      * The keychain will be named "lldb_codesign"
      * The keychain will be locked using the password "lldb_codesign"
      * The P12 archive will be encrypted with the password "lldb_codesign"

    This is intended to make it trivial to codesign utilities using the
    imported certificate, without exposing any local account information
    (eg, user's login keychain password). Please take these factors into
    account when evaluating security.
"""

log: Logger = logger.get_logger(__name__)

CFG = {
    "debug": False,
    "executable": os.path.basename(sys.argv[0]),
    "identity": "lldb_codesign",
    "id_file": None,  # from command line argument
    "keynick": "lldb",
    "keydb": None,
    "keypass": "lldb_codesign",
    "privileges": ["system.privilege.taskport"],
}


#
# Top-Level Commands
#


def cmd_check() -> int:
    keydb = CFG["keydb"]
    keypass = CFG["keypass"]
    identity = CFG["identity"]
    exe = CFG["executable"]

    for priv in CFG["privileges"]:
        print("Verifying privilege {} ... ".format(priv), end="")
        res_priv = security.verify_privilege(priv)
        if res_priv:
            print(OK("OK"))
        else:
            print(WARN("NOT SET"))
            log.debug(res_priv.value)
            print(WARN("WARNING"), "Privileges have not been set.")
            print(INFO("To set, run: {} --unsafe setup".format(exe)))

    print("Unlocking keychain ... ", end="")
    res_unlock = security.unlock_keychain(keydb, keypass)
    if res_unlock:
        print(OK("OK"))
    else:
        print(ERROR("FAILED"))
        log.debug(res_unlock.value)
        print(WARN("WARNING"), "Keychain not configured.")
        print(INFO("Please run: {} setup".format(exe)))
        return 1

    print("Verifying keychain ... ", end="")
    res_find = security.keychain_exists(keydb)
    if res_find:
        print(OK("OK"))
    else:
        print(ERROR("FAILED"))
        log.debug(res_find)
        print(INFO(res_find.value))
        return 2

    print("Searching for identity in keychain ... ", end="")
    res_find = security.identity_installed(identity, keydb)
    if res_find:
        print(OK("OK"))
    else:
        print(ERROR("FAILED"))
        log.debug(res_find)
        print(WARN("WARNING"), res_find.value)
        print(INFO("Please run: {} import".format(exe)))
        return 3

    print("Verifying identity ... ", end="")
    res_id = security.verify_identity(identity, keydb)
    if res_id:
        print(OK("OK"))
    else:
        print(ERROR("FAILED"))
        log.debug(res_id.value)
        print(WARN("WARNING"), "Unable to verify identity")
        print(INFO("Please run: {} import".format(exe)))
        return 4

    return 0


def cmd_clean() -> int:
    identity = CFG["identity"]
    keydb = CFG["keydb"]
    keypass = CFG["keypass"]

    print("Unlocking keychain ... ", end="")
    res_unlock = security.unlock_keychain(keydb, keypass)
    if res_unlock:
        print(OK("OK"))
    else:
        print(WARN("FAILED"))
        log.debug(res_unlock.value)
        print(INFO("Failed to unlock keychain."))

    print("Removing identity and trust settings ... ", end="")
    res_id = security.delete_identity(identity, keydb)
    if res_id:
        print(OK("OK"))
    else:
        print(WARN("Failed to remove identity"))
        log.debug(res_id.value)

    print("Backing up and removing keychain ... ", end="")
    res_key = security.delete_keychain(keydb, backup=True)
    if res_key:
        print(OK("OK"))
    else:
        print(WARN("Failed to remove keychain"))
        log.debug(res_id.value)

    return 0


def cmd_help(parser: ArgumentParser) -> int:
    print(OVERVIEW_TEXT.format(CFG["executable"], parser.format_help()))
    return 0


def cmd_import() -> int:
    exe = CFG["executable"]
    identity = CFG["identity"]
    keydb = CFG["keydb"]
    keypass = CFG["keypass"]
    id_file = CFG["id_file"]
    id_pass = identity

    _auth_sudo()

    if "SSH_CONNECTION" in os.environ or "TERM_SESSION_ID" not in os.environ:
        print(
            WARN("WARNING!"),
            "Remote console session detected!",
            "This procedure must be performed from the system console.",
        )

    print("Verifying privileges ... ", end="")
    res_verify_privs = security.verify_privileges(CFG["privileges"])
    if res_verify_privs:
        print(OK("OK"))
    else:
        print(WARN("WARNING"))
        log.debug(res_verify_privs)
        print(WARN("Privileges have not been set. Trust may fail."))
        print(INFO("To set privileges, run: {} --unsafe setup".format(exe)))

    print("Unlocking keychain ... ", end="")
    res_unlock = security.unlock_keychain(keydb, keypass)
    if res_unlock:
        print(OK("OK"))
    else:
        print(ERROR("FAILED"))
        log.debug(res_unlock)
        print(INFO("Failed to unlock keychain."), "Run: {} check".format(exe))
        return 1

    print("Importing new identity {} ... ".format(identity), end="")
    res_import = security.import_identity(keydb, keypass, identity, id_file, id_pass)
    if res_import:
        print(OK("OK"))
        log.debug(res_import.value)
    else:
        print(ERROR("FAILED"))
        log.debug(res_import)
        print(ERROR("ERROR"), res_import.value)
        if "exists" in res_import.value:
            print(WARN("To remove existing identity:"), "{} remove".format(exe))
        return 2

    print(WARN("This will test codesigning with the configured identity"))
    print(WARN("Please authenticate (if requested) and click 'Always Allow'"))

    print("Trusting identity ... ", end="")
    res_trust = security.trust_identity(identity, keydb)
    if res_trust:
        print(OK("OK"))
    else:
        print(ERROR("FAILED"))
        log.debug(res_trust)
        print(INFO("Trust unsuccessful:"), res_trust.value)
        if "unknown error" in res_trust.value:
            print(
                WARN("Please ensure this step is performed" " from the system console!")
            )

        print("Rolling back imported identity ... ", end="")
        res_remove = security.delete_identity(identity, keydb)
        if res_remove:
            print(OK("OK"))
        else:
            print(ERROR("FAILED"))
            log.debug(res_remove)
            print(res_trust.value)
            return 4
        return 3

    return 0


def cmd_lint() -> int:
    print(OK("Running linters... "))
    lint_problems = _run_linter()
    if lint_problems:
        print(WARN("Lint:"), len(lint_problems))
        map(log.warn, lint_problems)

    return len(lint_problems)


def cmd_prep() -> int:
    """Deliberately terse method for use in CI"""
    keydb = CFG["keydb"]
    keypass = CFG["keypass"]

    res_unlock = security.unlock_keychain(keydb, keypass)
    if not res_unlock:
        log.debug(res_unlock.value)
        print(ERROR("ERROR"), "Unable to access signing identity")
        return 1

    return 0


def cmd_remove() -> int:
    keydb = CFG["keydb"]
    keypass = CFG["keypass"]
    identity = CFG["identity"]

    print("Unlocking keychain ... ", end="")
    res_unlock = security.unlock_keychain(keydb, keypass)
    if res_unlock:
        print(OK("OK"))
    else:
        log.debug(res_unlock.value)
        print(ERROR("ERROR"), "Failed to unlock keychain")

    print("Removing identity from keychain ... ", end="")
    res_rm_id = security.delete_identity(identity, keydb)
    if res_rm_id:
        print(OK("OK"))
    else:
        print(WARN("FAILED"))
        log.debug(res_rm_id)
        print(WARN("WARNING"), "Failed to delete identity from keychain.")
        print(INFO(res_rm_id.value))

    return 0


def cmd_setup() -> int:
    keydb = CFG["keydb"]
    keypass = CFG["keypass"]
    exe = CFG["executable"]

    print("Configuring keychain ... ", end="")
    res_create = security.create_keychain(keydb, keypass)
    if res_create:
        print(OK("OK"))
    else:
        print(ERROR("FAILED"))
        log.debug(res_create)
        print(INFO("Keychain creation failed"))
        return 1

    print("Unlocking keychain ... ", end="")
    res_unlock = security.unlock_keychain(keydb, keypass)
    if res_unlock:
        print(OK("OK"))
    else:
        print(ERROR("FAILED"))
        log.debug(res_unlock)
        if "keychain could not be found" in res_unlock.value:
            print(INFO("Keychain creation failed"))
        else:
            print(INFO("Failed to unlock keychain"))
        print(INFO(res_unlock.value))
        return 2

    print("Adding keychain to search list ... ", end="")
    res_searchable = security.add_to_search_list(keydb)
    if res_searchable:
        print(OK("OK"))
    else:
        print(ERROR("FAILED"))
        log.debug(res_searchable)
        print(INFO("Failed to add keychain to search list"))
        print(WARN("codesign will not be able to find the signing identity."))
        return 3

    privs = CFG["privileges"]
    print("Checking privileges ... ", end="")
    if security.verify_privileges(privs):
        print(OK("OK"))
    else:
        print(INFO("NOT SET"))

        _auth_sudo()
        if not os.getenv(security.UNSAFE_FLAG, False):
            print(INFO("NOTE"), "Altering privileges may not be safe.")
            print(INFO("NOTE"), "Re-run with the --unsafe flag to enable.")
        else:
            priv_value = "allow"
            for priv in CFG["privileges"]:
                print("Setting privilege {} ... ".format(priv), end="")
                res_priv = security.authdb_privilege_write(priv, priv_value)
                if res_priv:
                    print(OK("OK"))
                else:
                    print(INFO("not set"))
                    log.debug(res_priv.value)
                    print(INFO("Privileges have not been set."))
                    print(INFO("Please re-run: {} setup".format(exe)))
                    return 4

    return 0


def cmd_test() -> int:
    _auth_sudo()

    print(OK("Running unittests... "))
    test_problems = _run_unittests()
    if test_problems:
        print(ERROR("Failures:"), len(test_problems))
        map(log.debug, test_problems)

    return len(test_problems)


def _auth_sudo() -> Result:
    cmd_sudo_check = shell.sudo_run(["-n"])
    if not cmd_sudo_check:
        print(WARN("If prompted, authenticate with sudo ... "))
        cmd_auth = shell.sudo_run(["ls"])
        if not cmd_auth:
            print(WARN("WARNING"), "sudo authentication failed")
        return cmd_auth
    else:
        return cmd_sudo_check


def _run_linter() -> list[str]:
    report_file = "flake8_report.pep8.txt"
    fmt = "lint: %(path)s:%(row)d:%(col)d: %(code)s %(text)s"
    lint_paths = ["./debugsign", "./dbsign/", "./unittests/"]

    cmd_flake = shell.run(
        ["flake8", "--tee", report_file, "--format={}".format(fmt)] + lint_paths
    )
    return cmd_flake.stdout.splitlines()


def _run_unittests() -> list[str]:
    try:
        import unittest2 as unittest
    except ImportError:
        import unittest

    tests = unittest.TestLoader().discover("unittests")
    test_result = unittest.TextTestRunner(
        stream=sys.stdout,
        verbosity=2,
    ).run(tests)

    problems = test_result.errors + test_result.failures
    return [str(problem[0]) for problem in problems]
