# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - Random number generator

"""
Internal module for random number generation.
This module should not be imported directly by users.
"""

from ctypes import c_size_t, create_string_buffer

from gmssl._lib import gmssl

# =============================================================================
# Random Number Generator
# =============================================================================


def rand_bytes(size):
    buf = create_string_buffer(size)
    gmssl.rand_bytes(buf, c_size_t(size))
    return buf.raw
