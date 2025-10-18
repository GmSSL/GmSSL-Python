# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - File operation utilities

"""
Internal module for safe file operations.
This module should not be imported directly by users.
"""

from contextlib import contextmanager
from ctypes import c_void_p

from gmssl._lib import libc


@contextmanager
def open_file(path, mode):
    """
    Context manager for safe file operations with automatic cleanup.

    Ensures file descriptors are always closed, even if an exception occurs.

    Args:
        path: File path (str or bytes)
        mode: File mode (e.g., "rb", "wb")

    Yields:
        c_void_p: File pointer for use with libc functions

    Raises:
        OSError: If file cannot be opened

    Example:
        with open_file("key.pem", "wb") as fp:
            gmssl.sm2_private_key_info_encrypt_to_pem(key, passwd, fp)
    """
    if isinstance(path, str):
        path = path.encode("utf-8")
    if isinstance(mode, str):
        mode = mode.encode("utf-8")

    libc.fopen.restype = c_void_p
    fp = libc.fopen(path, mode)

    if not fp:
        raise OSError(f"Cannot open file: {path.decode('utf-8')}")

    try:
        yield c_void_p(fp)
    finally:
        # Flush buffer before closing to ensure all data is written
        # This is especially important on macOS where buffering behavior differs
        libc.fflush(c_void_p(fp))
        libc.fclose(c_void_p(fp))
