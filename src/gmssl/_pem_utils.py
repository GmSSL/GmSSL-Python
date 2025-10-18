# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - PEM file utilities for Windows compatibility

"""
Internal module for PEM file operations with Windows FILE* workaround.
This module should not be imported directly by users.

On Windows, FILE* pointers cannot be passed across DLL boundaries due to
different C runtime versions. This module provides Python-based PEM I/O
that works around this limitation by using DER format + base64 encoding.

For Linux/macOS, this module provides wrapper functions that delegate to
the native FILE*-based functions for best performance.
"""

import base64
import sys
from ctypes import POINTER, byref, c_char_p, c_size_t, c_uint8, c_void_p, create_string_buffer

from gmssl._file_utils import open_file
from gmssl._lib import NativeError, gmssl, libc


def _write_pem_windows(path, name, der_data):
    """
    Write PEM file on Windows using Python file I/O.

    Args:
        path: File path (str)
        name: PEM label (e.g., "ENCRYPTED PRIVATE KEY")
        der_data: DER-encoded data (bytes)
    """
    with open(path, "wb") as f:
        f.write(f"-----BEGIN {name}-----\n".encode("ascii"))
        # Base64 encode with 64 characters per line (PEM standard)
        b64_data = base64.b64encode(der_data)
        for i in range(0, len(b64_data), 64):
            f.write(b64_data[i : i + 64])
            f.write(b"\n")
        f.write(f"-----END {name}-----\n".encode("ascii"))


def _read_pem_windows(path, name):
    """
    Read PEM file on Windows using Python file I/O.

    Args:
        path: File path (str)
        name: PEM label (e.g., "ENCRYPTED PRIVATE KEY")

    Returns:
        bytes: DER-encoded data
    """
    begin_marker = f"-----BEGIN {name}-----"
    end_marker = f"-----END {name}-----"

    with open(path) as f:
        lines = f.readlines()

    # Find begin and end markers
    begin_idx = None
    end_idx = None
    for i, line in enumerate(lines):
        line = line.strip()
        if line == begin_marker:
            begin_idx = i
        elif line == end_marker:
            end_idx = i
            break

    if begin_idx is None or end_idx is None:
        raise ValueError(f"Invalid PEM file: missing {name} markers")

    # Extract base64 data
    b64_data = "".join(line.strip() for line in lines[begin_idx + 1 : end_idx])
    return base64.b64decode(b64_data)


# =============================================================================
# SM2 Public Key PEM Operations
# =============================================================================


def sm2_public_key_info_to_pem_windows(key, path):
    """
    Export SM2 public key to PEM file (Windows-compatible).
    """
    # Use stack buffer like the C implementation
    buf = create_string_buffer(512)
    p = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    outlen = c_size_t(0)

    if gmssl.sm2_public_key_info_to_der(byref(key), byref(p), byref(outlen)) != 1:
        raise NativeError("sm2_public_key_info_to_der failed")

    _write_pem_windows(path, "PUBLIC KEY", buf.raw[: outlen.value])


def sm2_public_key_info_from_pem_windows(key, path):
    """
    Import SM2 public key from PEM file (Windows-compatible).
    """
    der_data = _read_pem_windows(path, "PUBLIC KEY")
    # Create a buffer and pointer like the C implementation
    buf = create_string_buffer(der_data)
    cp = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    der_len = c_size_t(len(der_data))

    if gmssl.sm2_public_key_info_from_der(byref(key), byref(cp), byref(der_len)) != 1:
        raise NativeError("sm2_public_key_info_from_der failed")


# =============================================================================
# SM2 Private Key PEM Operations
# =============================================================================


def sm2_private_key_info_encrypt_to_pem_windows(key, path, passwd):
    """
    Export SM2 encrypted private key to PEM file (Windows-compatible).

    Uses DER export + Python file I/O to avoid FILE* cross-DLL issues.
    """
    # Use stack buffer like the C implementation
    buf = create_string_buffer(1024)
    p = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    outlen = c_size_t(0)

    if gmssl.sm2_private_key_info_encrypt_to_der(byref(key), passwd, byref(p), byref(outlen)) != 1:
        raise NativeError("sm2_private_key_info_encrypt_to_der failed")

    _write_pem_windows(path, "ENCRYPTED PRIVATE KEY", buf.raw[: outlen.value])


def sm2_private_key_info_decrypt_from_pem_windows(key, path, passwd):
    """
    Import SM2 encrypted private key from PEM file (Windows-compatible).
    """
    # Read PEM file and decode to DER
    der_data = _read_pem_windows(path, "ENCRYPTED PRIVATE KEY")

    # Parse DER format - create buffer and pointer like the C implementation
    buf = create_string_buffer(der_data)
    cp = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    der_len = c_size_t(len(der_data))
    attrs_ptr = c_void_p()
    attrs_len = c_size_t()

    if (
        gmssl.sm2_private_key_info_decrypt_from_der(
            byref(key),
            byref(attrs_ptr),
            byref(attrs_len),
            passwd,
            byref(cp),
            byref(der_len),
        )
        != 1
    ):
        raise NativeError("sm2_private_key_info_decrypt_from_der failed")


# =============================================================================
# SM9 Encryption Master Key PEM Operations
# =============================================================================


def sm9_enc_master_public_key_to_pem_windows(mpk, path):
    """
    Export SM9 encryption master public key to PEM file (Windows-compatible).
    """
    # Use stack buffer like the C implementation
    buf = create_string_buffer(1024)
    p = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    outlen = c_size_t(0)

    if gmssl.sm9_enc_master_public_key_to_der(byref(mpk), byref(p), byref(outlen)) != 1:
        raise NativeError("sm9_enc_master_public_key_to_der failed")

    _write_pem_windows(path, "SM9 ENC MASTER PUBLIC KEY", buf.raw[: outlen.value])


def sm9_enc_master_public_key_from_pem_windows(mpk, path):
    """
    Import SM9 encryption master public key from PEM file (Windows-compatible).
    """
    der_data = _read_pem_windows(path, "SM9 ENC MASTER PUBLIC KEY")
    buf = create_string_buffer(der_data)
    cp = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    der_len = c_size_t(len(der_data))

    if gmssl.sm9_enc_master_public_key_from_der(byref(mpk), byref(cp), byref(der_len)) != 1:
        raise NativeError("sm9_enc_master_public_key_from_der failed")


def sm9_enc_master_key_info_encrypt_to_pem_windows(msk, path, passwd):
    """
    Export SM9 encryption master key to PEM file (Windows-compatible).
    """
    # Use stack buffer like the C implementation
    buf = create_string_buffer(1024)
    p = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    outlen = c_size_t(0)

    if (
        gmssl.sm9_enc_master_key_info_encrypt_to_der(byref(msk), passwd, byref(p), byref(outlen))
        != 1
    ):
        raise NativeError("sm9_enc_master_key_info_encrypt_to_der failed")

    _write_pem_windows(path, "ENCRYPTED SM9 ENC MASTER KEY", buf.raw[: outlen.value])


def sm9_enc_master_key_info_decrypt_from_pem_windows(msk, path, passwd):
    """
    Import SM9 encryption master key from PEM file (Windows-compatible).
    """
    der_data = _read_pem_windows(path, "ENCRYPTED SM9 ENC MASTER KEY")
    buf = create_string_buffer(der_data)
    cp = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    der_len = c_size_t(len(der_data))

    if (
        gmssl.sm9_enc_master_key_info_decrypt_from_der(
            byref(msk), passwd, byref(cp), byref(der_len)
        )
        != 1
    ):
        raise NativeError("sm9_enc_master_key_info_decrypt_from_der failed")


# =============================================================================
# SM9 Signature Master Key PEM Operations
# =============================================================================


def sm9_sign_master_public_key_to_pem_windows(mpk, path):
    """
    Export SM9 signature master public key to PEM file (Windows-compatible).
    """
    # Use stack buffer like the C implementation
    buf = create_string_buffer(1024)
    p = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    outlen = c_size_t(0)

    if gmssl.sm9_sign_master_public_key_to_der(byref(mpk), byref(p), byref(outlen)) != 1:
        raise NativeError("sm9_sign_master_public_key_to_der failed")

    _write_pem_windows(path, "SM9 SIGN MASTER PUBLIC KEY", buf.raw[: outlen.value])


def sm9_sign_master_public_key_from_pem_windows(mpk, path):
    """
    Import SM9 signature master public key from PEM file (Windows-compatible).
    """
    der_data = _read_pem_windows(path, "SM9 SIGN MASTER PUBLIC KEY")
    buf = create_string_buffer(der_data)
    cp = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    der_len = c_size_t(len(der_data))

    if gmssl.sm9_sign_master_public_key_from_der(byref(mpk), byref(cp), byref(der_len)) != 1:
        raise NativeError("sm9_sign_master_public_key_from_der failed")


def sm9_sign_master_key_info_encrypt_to_pem_windows(msk, path, passwd):
    """
    Export SM9 signature master key to PEM file (Windows-compatible).
    """
    # Use stack buffer like the C implementation
    buf = create_string_buffer(1024)
    p = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    outlen = c_size_t(0)

    if (
        gmssl.sm9_sign_master_key_info_encrypt_to_der(byref(msk), passwd, byref(p), byref(outlen))
        != 1
    ):
        raise NativeError("sm9_sign_master_key_info_encrypt_to_der failed")

    _write_pem_windows(path, "ENCRYPTED SM9 SIGN MASTER KEY", buf.raw[: outlen.value])


def sm9_sign_master_key_info_decrypt_from_pem_windows(msk, path, passwd):
    """
    Import SM9 signature master key from PEM file (Windows-compatible).
    """
    der_data = _read_pem_windows(path, "ENCRYPTED SM9 SIGN MASTER KEY")
    buf = create_string_buffer(der_data)
    cp = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    der_len = c_size_t(len(der_data))

    if (
        gmssl.sm9_sign_master_key_info_decrypt_from_der(
            byref(msk), passwd, byref(cp), byref(der_len)
        )
        != 1
    ):
        raise NativeError("sm9_sign_master_key_info_decrypt_from_der failed")


# =============================================================================
# SM9 Encryption Key PEM Operations
# =============================================================================


def sm9_enc_key_info_encrypt_to_pem_windows(key, path, passwd):
    """
    Export SM9 encryption key to PEM file (Windows-compatible).
    """
    # Use stack buffer like the C implementation
    buf = create_string_buffer(1024)
    p = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    outlen = c_size_t(0)

    if gmssl.sm9_enc_key_info_encrypt_to_der(byref(key), passwd, byref(p), byref(outlen)) != 1:
        raise NativeError("sm9_enc_key_info_encrypt_to_der failed")

    _write_pem_windows(path, "ENCRYPTED SM9 ENC PRIVATE KEY", buf.raw[: outlen.value])


def sm9_enc_key_info_decrypt_from_pem_windows(key, path, passwd):
    """
    Import SM9 encryption key from PEM file (Windows-compatible).
    """
    der_data = _read_pem_windows(path, "ENCRYPTED SM9 ENC PRIVATE KEY")
    buf = create_string_buffer(der_data)
    cp = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    der_len = c_size_t(len(der_data))

    if gmssl.sm9_enc_key_info_decrypt_from_der(byref(key), passwd, byref(cp), byref(der_len)) != 1:
        raise NativeError("sm9_enc_key_info_decrypt_from_der failed")


# =============================================================================
# SM9 Signature Key PEM Operations
# =============================================================================


def sm9_sign_key_info_encrypt_to_pem_windows(key, path, passwd):
    """
    Export SM9 signature key to PEM file (Windows-compatible).
    """
    # Use stack buffer like the C implementation
    buf = create_string_buffer(1024)
    p = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    outlen = c_size_t(0)

    if gmssl.sm9_sign_key_info_encrypt_to_der(byref(key), passwd, byref(p), byref(outlen)) != 1:
        raise NativeError("sm9_sign_key_info_encrypt_to_der failed")

    _write_pem_windows(path, "ENCRYPTED SM9 SIGN PRIVATE KEY", buf.raw[: outlen.value])


def sm9_sign_key_info_decrypt_from_pem_windows(key, path, passwd):
    """
    Import SM9 signature key from PEM file (Windows-compatible).
    """
    der_data = _read_pem_windows(path, "ENCRYPTED SM9 SIGN PRIVATE KEY")
    buf = create_string_buffer(der_data)
    cp = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    der_len = c_size_t(len(der_data))

    if gmssl.sm9_sign_key_info_decrypt_from_der(byref(key), passwd, byref(cp), byref(der_len)) != 1:
        raise NativeError("sm9_sign_key_info_decrypt_from_der failed")


# =============================================================================
# X.509 Certificate PEM Operations
# =============================================================================


def x509_cert_to_pem_windows(cert, certlen, path):
    """
    Export X.509 certificate to PEM file (Windows-compatible).
    """
    _write_pem_windows(path, "CERTIFICATE", bytes(cert[:certlen]))


def x509_cert_from_pem_windows(path):
    """
    Import X.509 certificate from PEM file (Windows-compatible).

    Returns:
        tuple: (cert_data, cert_len) - Certificate DER data and length
    """
    der_data = _read_pem_windows(path, "CERTIFICATE")
    buf = create_string_buffer(der_data)
    cp = POINTER(c_uint8)(c_uint8.from_buffer(buf))
    der_len = c_size_t(len(der_data))

    cert_ptr = c_void_p()
    cert_len = c_size_t()

    if gmssl.x509_cert_from_der(byref(cert_ptr), byref(cert_len), byref(cp), byref(der_len)) != 1:
        raise NativeError("x509_cert_from_der failed")

    # Copy certificate data
    cert_data = create_string_buffer(cert_len.value)
    libc.memcpy(cert_data, cert_ptr, cert_len.value)

    return cert_data, cert_len.value


# =============================================================================
# Cross-Platform Wrapper Functions
# =============================================================================


def _call_platform_pem_function(func_name, key, path, file_mode, extra_args=()):
    """
    Generic cross-platform wrapper for PEM operations.

    Automatically selects Windows-compatible or FILE*-based implementation.
    Windows function name is derived by appending '_windows' to func_name.

    Args:
        func_name: Base function name (e.g., "sm2_public_key_info_to_pem")
        key: Key object (SM2Key, Sm9EncMasterKey, etc.)
        path: File path (str)
        file_mode: File mode for non-Windows platforms ("rb" or "wb")
        extra_args: Additional arguments tuple (e.g., (c_char_p(passwd),))

    Raises:
        NativeError: If the operation fails
    """
    if sys.platform == "win32":
        # Windows: Use Python-based implementation
        windows_func = globals()[f"{func_name}_windows"]
        windows_func(key, path, *extra_args)
    else:
        # Linux/macOS: Use FILE* for best performance
        with open_file(path, file_mode) as fp:
            gmssl_func = getattr(gmssl, func_name)
            if gmssl_func(byref(key), *extra_args, fp) != 1:
                raise NativeError(f"{func_name} failed")


def pem_export_encrypted_key(key, path, passwd, export_func_name):
    """
    Cross-platform wrapper for exporting encrypted keys to PEM.

    Args:
        key: Key object (SM2Key, Sm9EncMasterKey, etc.)
        path: File path (str)
        passwd: Password (bytes)
        export_func_name: Name of the gmssl export function
                         (e.g., "sm2_private_key_info_encrypt_to_pem")
    """
    _call_platform_pem_function(export_func_name, key, path, "wb", extra_args=(c_char_p(passwd),))


def pem_import_encrypted_key(key, path, passwd, import_func_name):
    """
    Cross-platform wrapper for importing encrypted keys from PEM.

    Args:
        key: Key object (SM2Key, Sm9EncMasterKey, etc.)
        path: File path (str)
        passwd: Password (bytes)
        import_func_name: Name of the gmssl import function
                         (e.g., "sm2_private_key_info_decrypt_from_pem")
    """
    _call_platform_pem_function(import_func_name, key, path, "rb", extra_args=(c_char_p(passwd),))


def pem_export_public_key(key, path, export_func_name):
    """
    Cross-platform wrapper for exporting public keys to PEM.

    Args:
        key: Key object (SM2Key, etc.)
        path: File path (str)
        export_func_name: Name of the gmssl export function
                         (e.g., "sm2_public_key_info_to_pem")
    """
    _call_platform_pem_function(export_func_name, key, path, "wb")


def pem_import_public_key(key, path, import_func_name):
    """
    Cross-platform wrapper for importing public keys from PEM.

    Args:
        key: Key object (SM2Key, etc.)
        path: File path (str)
        import_func_name: Name of the gmssl import function
                         (e.g., "sm2_public_key_info_from_pem")
    """
    _call_platform_pem_function(import_func_name, key, path, "rb")
