"""
Tiny CLI for Android Decryptor
"""

from contextlib import ExitStack
from getpass import getpass
from os import environ
from sys import argv, stderr, stdin, stdout

from .decryptor import decrypt_android_backup


def get_password() -> bytes:
    """
    Get user password.

    Returns:
        UTF-8 encoded password.
    """

    pwd = environ.get("AB_DECRYPT_PASSWORD")
    if pwd is None:
        pwd = getpass("Password: ")

    return pwd.encode()


def main():
    """
    Command Line Interface
    """

    if len(argv) > 3 or len(argv) == 2 and argv[1] in {"-h", "--help"}:
        print(f"Usage: {argv[0]} [- | infile] [- | outfile]", file=stderr)
        exit(2)

    with ExitStack() as stack:
        if len(argv) > 1 and argv[1] != "-":
            in_stream = stack.enter_context(open(argv[1], "rb"))
        else:
            in_stream = stdin.buffer

        if len(argv) > 2 and argv[2] != "-":
            out_stream = stack.enter_context(open(argv[2], "wb"))
        else:
            out_stream = stdout.buffer

        decrypt_android_backup(in_stream, out_stream, get_password)
