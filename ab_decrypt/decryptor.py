"""
Decryptor for android backups

See
https://github.com/aosp-mirror/platform_frameworks_base/blob/master/services/backup/java/com/android/server/backup/fullbackup/PerformAdbBackupTask.java
for the android implementation.
"""

from abc import ABC, abstractmethod
from typing import BinaryIO, Callable, Tuple
from zlib import decompressobj

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

backend = default_backend()


class AbstractWriter(ABC):
    """
    ABC for chaining output modifying funtions together.
    """

    @abstractmethod
    def write(self, buf: bytes) -> None:
        """
        Write buf to stream

        Args:
            buf: data to write
        """

    @abstractmethod
    def flush(self) -> None:
        """
        Finish output. Must not call write afterwards.
        """


class StreamWriter(AbstractWriter):
    """
    Write to python stream
    """

    def __init__(self, stream: BinaryIO) -> None:
        """
        Args:
            stream: Target stream
        """

        self.stream = stream

    def write(self, buf: bytes) -> None:
        """
        Write buf to stream

        Args:
            buf: data to write
        """

        self.stream.write(buf)

    def flush(self) -> None:
        """
        Finish output. Must not call write afterwards.
        """

        self.stream.flush()


class ZlibDecompressor(AbstractWriter):
    """
    Decompress zlib
    """

    def __init__(self, stream: AbstractWriter) -> None:
        """
        Args:
            stream: Target stream
        """

        self.stream = stream
        self.decompressor = decompressobj()

    def write(self, buf: bytes) -> None:
        """
        Write buf to stream

        Args:
            buf: data to write
        """

        self.stream.write(self.decompressor.decompress(buf))

    def flush(self) -> None:
        """
        Finish output. Must not call write afterwards.
        """

        self.stream.write(self.decompressor.flush())
        self.stream.flush()


class PKCS7Unpadder(AbstractWriter):
    """
    Unpad PKCS#7
    """

    def __init__(self, stream: AbstractWriter) -> None:
        """
        Args:
            stream: Target stream
        """

        self.stream = stream
        self.unpadder = padding.PKCS7(128).unpadder()

    def write(self, buf: bytes) -> None:
        """
        Write buf to stream

        Args:
            buf: data to write
        """

        self.stream.write(self.unpadder.update(buf))

    def flush(self) -> None:
        """
        Finish output. Must not call write afterwards.
        """

        self.stream.write(self.unpadder.finalize())
        self.stream.flush()


class Aes256Decryptor(AbstractWriter):
    """
    Decrypt AES-CBC stream
    """

    def __init__(self, stream: AbstractWriter, key: bytes, iv: bytes) -> None:
        """
        Args:
            stream: Target stream
            key: AES key (16, 24 or 32 bytes)
            iv: IV for CBC (16 bytes)
        """

        self.stream = PKCS7Unpadder(stream)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        self.decryptor = cipher.decryptor()

    def write(self, buf: bytes) -> None:
        """
        Write buf to stream

        Args:
            buf: data to write
        """

        self.stream.write(self.decryptor.update(buf))

    def flush(self) -> None:
        """
        Finish output. Must not call write afterwards.
        """

        self.stream.write(self.decryptor.finalize())
        self.stream.flush()


def utf8_encode(buf: bytes) -> bytes:
    """
    Stupid java bytes-to-string-to-bytes encoding.

    Args:
        buf: data to encode

    Returns:
        utf8 encoded data
    """

    return "".join(chr(i if i < 0x80 else i + 0xFF00) for i in buf).encode()


def derive_aes_256_key(
    pwd: bytes, pwd_salt: bytes, mk_ck_salt: bytes, rounds: int, uk_iv: bytes, mk_blob: bytes,
) -> Tuple[bytes, bytes]:
    """
    Derive key and IV from password.

    Args:
        pwd: User's password, utf8 encoded
        pwd_salt: PBKDF2 salt for user password
        mk_ck_salt: PBKDF2 salt for master key
        rounds: Number of PBKDF2 rounds
        uk_iv: CBC IV for user key
        mk_blob: Encrypted master key blob

    Returns:
        Master key and IV
    """

    # Derive user key
    uk = PBKDF2HMAC(
        algorithm=hashes.SHA1(), length=32, salt=pwd_salt, iterations=rounds, backend=backend,
    ).derive(pwd)

    # Decrypt master key blob
    cipher = Cipher(algorithms.AES(uk), modes.CBC(uk_iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    blob = bytearray(unpadder.update(decryptor.update(mk_blob) + decryptor.finalize()) + unpadder.finalize())

    # Split values from master key blob
    mk_iv_len = blob[0]
    mk_iv = blob[1 : mk_iv_len + 1]
    del blob[: mk_iv_len + 1]

    mk_len = blob[0]
    mk = blob[1 : mk_len + 1]
    del blob[: mk_len + 1]

    mk_ck_len = blob[0]
    if len(blob) - 1 != mk_ck_len:
        raise ValueError
    mk_ck_0 = bytes(blob[1:])

    # Calculate and compare checksum
    mk_ck_1 = PBKDF2HMAC(
        algorithm=hashes.SHA1(), length=mk_ck_len, salt=mk_ck_salt, iterations=rounds, backend=backend,
    ).derive(utf8_encode(mk))

    if mk_ck_0 != mk_ck_1:
        raise ValueError("Bad password")

    return mk, mk_iv


def read_hex(stream: BinaryIO) -> bytes:
    """
    Read HEX line from stream and decode as bytes

    Args:
        stream: stream to read from

    Returns: decoded bytes
    """
    return bytes.fromhex(stream.readline().decode())


def decrypt_android_backup(in_stream: BinaryIO, out_stream: BinaryIO, pw_callback: Callable[[], bytes]) -> None:
    """
    Decrypt an android backup.

    Args:
        in_stream: Input stream
        out_stream: Output stream
        pw_callback: Callback function to retrieve user password
    """

    writer: AbstractWriter = StreamWriter(out_stream)

    if in_stream.readline() != b"ANDROID BACKUP\n":
        raise ValueError("Bad magic")
    version = int(in_stream.readline())
    compressed = int(in_stream.readline())
    encr_algo = in_stream.readline().strip().decode()

    if compressed:
        writer = ZlibDecompressor(writer)

    if encr_algo == "none":
        pass
    elif encr_algo == "AES-256":
        pwd = pw_callback()
        pwd_salt = read_hex(in_stream)
        mk_ck_salt = read_hex(in_stream)
        rounds = int(in_stream.readline())
        uk_iv = read_hex(in_stream)
        mk_blob = read_hex(in_stream)

        try:
            key, iv = derive_aes_256_key(pwd, pwd_salt, mk_ck_salt, rounds, uk_iv, mk_blob)
        except Exception as ex:
            raise ValueError("Bad password!") from ex

        writer = Aes256Decryptor(writer, key, iv)
    else:
        raise ValueError(f"Unknown encryption algorithm: {encr_algo}")

    while True:
        buf = in_stream.read(4096)
        if not buf:
            break
        writer.write(buf)
    writer.flush()
