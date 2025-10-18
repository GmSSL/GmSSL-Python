# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - Version information

"""
Internal module for version information.
This module should not be imported directly by users.
"""

from ctypes import c_char_p

from gmssl._lib import gmssl

# =============================================================================
# Version Information
# =============================================================================

GMSSL_PYTHON_VERSION = "2.2.2"


def gmssl_library_version_num():
    return gmssl.gmssl_version_num()


def gmssl_library_version_str():
    gmssl.gmssl_version_str.restype = c_char_p
    return gmssl.gmssl_version_str().decode("ascii")


GMSSL_LIBRARY_VERSION = gmssl_library_version_str()
