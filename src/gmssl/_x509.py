# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - X.509 certificate parsing and validation

"""
Internal module for X.509 certificate handling.
This module should not be imported directly by users.
"""

import datetime
import sys
from ctypes import byref, c_char_p, c_int, c_size_t, c_ulong, c_void_p, create_string_buffer

from gmssl._constants import _ASN1_TAG_SEQUENCE, _ASN1_TAG_SET, _ASN1_TAG_IA5String
from gmssl._file_utils import open_file
from gmssl._lib import NativeError, gmssl, libc
from gmssl._pem_utils import x509_cert_from_pem_windows, x509_cert_to_pem_windows
from gmssl._sm2 import Sm2Key

# =============================================================================
# X.509 Certificate Parsing Utilities
# =============================================================================


def gmssl_parse_attr_type_and_value(name, d, dlen):
    oid = c_int()
    tag = c_int()
    val = c_void_p()
    vlen = c_size_t()

    if gmssl.x509_name_type_from_der(byref(oid), byref(d), byref(dlen)) != 1:
        raise NativeError("libgmssl inner error")
    gmssl.x509_name_type_name.restype = c_char_p
    oid_name = gmssl.x509_name_type_name(oid).decode("ascii")

    if oid_name == "emailAddress":
        if (
            gmssl.asn1_ia5_string_from_der_ex(
                _ASN1_TAG_IA5String, byref(val), byref(vlen), byref(d), byref(dlen)
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")
    else:
        if (
            gmssl.x509_directory_name_from_der(
                byref(tag), byref(val), byref(vlen), byref(d), byref(dlen)
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")

    if dlen.value != 0:
        raise ValueError("invalid der encoding")

    value = create_string_buffer(vlen.value)
    libc.memcpy(value, val, vlen)

    name[oid_name] = value.raw.decode("utf-8")
    return True


def gmssl_parse_rdn(name, d, dlen):
    v = c_void_p()
    vlen = c_size_t()

    while dlen.value > 0:
        if (
            gmssl.asn1_type_from_der(
                _ASN1_TAG_SEQUENCE, byref(v), byref(vlen), byref(d), byref(dlen)
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")

        if gmssl_parse_attr_type_and_value(name, v, vlen) != 1:
            raise NativeError("libgmssl inner error")

    return True


# https://stacktuts.com/how-to-correctly-pass-pointer-to-pointer-into-dll-in-python-and-ctypes#
def gmssl_parse_name(name, d, dlen):
    v = c_void_p()
    vlen = c_size_t()

    while dlen.value > 0:
        if (
            gmssl.asn1_nonempty_type_from_der(
                c_int(_ASN1_TAG_SET), byref(v), byref(vlen), byref(d), byref(dlen)
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")
        gmssl_parse_rdn(name, v, vlen)
    return True


class Validity:
    def __init__(self, not_before, not_after):
        self.not_before = datetime.datetime.fromtimestamp(not_before)
        self.not_after = datetime.datetime.fromtimestamp(not_after)


class Sm2Certificate:
    def import_pem(self, path):
        if sys.platform == "win32":
            # Windows: Use Python-based PEM reading to avoid FILE* issues
            cert_data, cert_len = x509_cert_from_pem_windows(path)
            self._cert = cert_data
        else:
            # Linux/macOS: Use FILE* for best performance
            cert = c_void_p()
            certlen = c_size_t()
            if (
                gmssl.x509_cert_new_from_file(byref(cert), byref(certlen), path.encode("utf-8"))
                != 1
            ):
                raise NativeError("libgmssl inner error")

            self._cert = create_string_buffer(certlen.value)
            libc.memcpy(self._cert, cert, certlen)
            libc.free(cert)

    def get_raw(self):
        return self._cert

    def export_pem(self, path):
        if sys.platform == "win32":
            # Windows: Use Python-based PEM writing to avoid FILE* issues
            x509_cert_to_pem_windows(self._cert, len(self._cert), path)
        else:
            # Linux/macOS: Use FILE* for best performance
            with open_file(path, "wb") as fp:
                if gmssl.x509_cert_to_pem(self._cert, c_size_t(len(self._cert)), fp) != 1:
                    raise NativeError("libgmssl inner error")

    def get_serial_number(self):
        serial_ptr = c_void_p()
        serial_len = c_size_t()

        if (
            gmssl.x509_cert_get_issuer_and_serial_number(
                self._cert,
                c_size_t(len(self._cert)),
                None,
                None,
                byref(serial_ptr),
                byref(serial_len),
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")

        serial = create_string_buffer(serial_len.value)
        libc.memcpy(serial, serial_ptr, serial_len)
        return serial.raw

    def get_issuer(self):
        issuer_ptr = c_void_p()
        issuer_len = c_size_t()
        if (
            gmssl.x509_cert_get_issuer(
                self._cert,
                c_size_t(len(self._cert)),
                byref(issuer_ptr),
                byref(issuer_len),
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")
        issuer_raw = create_string_buffer(issuer_len.value)
        libc.memcpy(issuer_raw, issuer_ptr, issuer_len)

        issuer = {"raw_data": issuer_raw.raw}
        gmssl_parse_name(issuer, issuer_ptr, issuer_len)
        return issuer

    def get_subject(self):
        subject_ptr = c_void_p()
        subject_len = c_size_t()
        if (
            gmssl.x509_cert_get_subject(
                self._cert,
                c_size_t(len(self._cert)),
                byref(subject_ptr),
                byref(subject_len),
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")
        subject_raw = create_string_buffer(subject_len.value)
        libc.memcpy(subject_raw, subject_ptr, subject_len)

        subject = {"raw_data": subject_raw.raw}
        gmssl_parse_name(subject, subject_ptr, subject_len)
        return subject

    def get_subject_public_key(self):
        public_key = Sm2Key()
        gmssl.x509_cert_get_subject_public_key(
            self._cert, c_size_t(len(self._cert)), byref(public_key)
        )
        public_key._has_private_key = False
        public_key._has_public_key = True
        return public_key

    def get_validity(self):
        not_before = c_ulong()
        not_after = c_ulong()
        if (
            gmssl.x509_cert_get_details(
                self._cert,
                c_size_t(len(self._cert)),
                None,
                None,
                None,
                None,
                None,
                None,
                byref(not_before),
                byref(not_after),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            != 1
        ):
            raise NativeError("libgmssl inner error")
        return Validity(not_before.value, not_after.value)

    def verify_by_ca_certificate(self, cacert, sm2_id):
        cacert_raw = cacert.get_raw()
        sm2_id = sm2_id.encode("utf-8")

        return (
            gmssl.x509_cert_verify_by_ca_cert(
                self._cert,
                c_size_t(len(self._cert)),
                cacert_raw,
                c_size_t(len(cacert_raw)),
                c_char_p(sm2_id),
                c_size_t(len(sm2_id)),
            )
            == 1
        )
