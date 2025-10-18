# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# GmSSL-Python - Library loading and exceptions

"""
Internal module for GmSSL library loading and exception definitions.
This module should not be imported directly by users.
"""

import os
import platform
import sys
from ctypes import cdll
from ctypes.util import find_library

# =============================================================================
# Library Loading
# =============================================================================

# Minimum required GmSSL version (3.1.1)
REQUIRED_VERSION = 30101
GMSSL_REPO_URL = "https://github.com/guanzhi/GmSSL"


def _get_platform_library_name():
    """
    Get platform-specific library name for bundled GmSSL library.

    Returns:
        str: Library filename for current platform

    Raises:
        ValueError: If platform/architecture is not supported
    """
    if sys.platform == "darwin":
        return "libgmssl.3.dylib"

    if sys.platform == "win32":
        return "gmssl.dll"

    # Linux and other Unix-like systems - detect architecture
    machine = platform.machine().lower()
    if machine in ("aarch64", "arm64"):
        return "libgmssl.so.3.aarch64"

    if machine in ("x86_64", "amd64"):
        return "libgmssl.so.3.x86_64"

    # Unsupported architecture
    raise ValueError(
        f"Unsupported Linux architecture: {machine}\n"
        f"Bundled GmSSL libraries are only available for:\n"
        f"  - x86_64 (amd64)\n"
        f"  - aarch64 (arm64)\n"
        f"Please install GmSSL manually: {GMSSL_REPO_URL}"
    )


def _get_bundled_library_path():
    """
    Get full path to bundled GmSSL library.

    Returns:
        str or None: Path to bundled library if exists, None otherwise
    """
    try:
        lib_name = _get_platform_library_name()
    except ValueError:
        return None

    lib_dir = os.path.join(os.path.dirname(__file__), "_libs")
    lib_path = os.path.join(lib_dir, lib_name)

    return lib_path if os.path.exists(lib_path) else None


def _check_library_version(lib):
    """
    Check if loaded library meets version requirement.

    Args:
        lib: Loaded CDLL library instance

    Returns:
        tuple: (is_valid, version_number)
    """
    version = lib.gmssl_version_num()
    return version >= REQUIRED_VERSION, version


def _load_gmssl_library():
    """
    Load GmSSL library with version check and smart fallback.

    Priority:
    1. System library (if version >= 3.1.1)
    2. Bundled library (fallback if system lib too old or missing)

    Returns:
        CDLL: Loaded GmSSL library instance

    Raises:
        ValueError: If no suitable library found or version too old
    """
    # Try system library first
    system_lib_path = find_library("gmssl")
    if system_lib_path:
        lib = cdll.LoadLibrary(system_lib_path)
        is_valid, version = _check_library_version(lib)
        if is_valid:
            return lib
        # System library too old, will try bundled as fallback

    # Try bundled library
    bundled_lib_path = _get_bundled_library_path()
    if bundled_lib_path:
        lib = cdll.LoadLibrary(bundled_lib_path)
        is_valid, version = _check_library_version(lib)
        if is_valid:
            return lib

    # No suitable library found - provide helpful error message
    if system_lib_path:
        # System library exists but too old
        raise ValueError(
            f"GmSSL version too old: {version} < {REQUIRED_VERSION} (required)\n"
            f"Loaded from: {system_lib_path}\n"
            f"Please upgrade GmSSL: {GMSSL_REPO_URL}"
        )

    # No library found at all
    raise ValueError(
        "GmSSL library not found. Install it via:\n"
        f"  - System package: {GMSSL_REPO_URL}\n"
        "  - Or reinstall gmssl_python (should include bundled library)"
    )


# Load GmSSL library
gmssl = _load_gmssl_library()

# Load C standard library for file operations
if sys.platform == "win32":
    libc = cdll.LoadLibrary(find_library("msvcrt"))
else:
    libc = cdll.LoadLibrary(find_library("c"))

# =============================================================================
# Exceptions
# =============================================================================


class NativeError(Exception):
    """
    GmSSL library inner error
    """


class StateError(Exception):
    """
    Crypto state error
    """


# =============================================================================
# Error Handling Utilities
# =============================================================================


def raise_on_error(result, func_name):
    """
    Raise NativeError if gmssl function returns error.

    Args:
        result: Return value from gmssl function (1 = success, other = error)
        func_name: Name of the gmssl function that was called

    Raises:
        NativeError: If result != 1

    Example:
        raise_on_error(gmssl.sm2_key_generate(byref(key)), "sm2_key_generate")
    """
    if result != 1:
        raise NativeError(f"{func_name} failed")


def check_gmssl_error(func):
    """
    Decorator that automatically checks gmssl function call results.

    The decorated function should return a tuple of (result, func_name) or
    just call gmssl functions that return 1 on success.

    Example 1 - Return tuple:
        @check_gmssl_error
        def generate_key(self):
            result = gmssl.sm2_key_generate(byref(self))
            return result, "sm2_key_generate"

    Example 2 - Check inline:
        @check_gmssl_error
        def generate_key(self):
            gmssl.sm2_key_generate(byref(self)) | "sm2_key_generate"

    Note: For simple cases, use raise_on_error() directly instead.
    """
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        # If function returns a tuple (result, func_name), check the result
        if isinstance(result, tuple) and len(result) == 2:
            ret_val, func_name = result
            if ret_val != 1:
                raise NativeError(f"{func_name} failed")
            return ret_val
        # Otherwise return as-is (function already handled errors)
        return result

    return wrapper


class GmsslCall:
    """
    Callable wrapper for gmssl functions with automatic error checking.

    This provides a cleaner alternative to raise_on_error() for repeated calls
    to the same gmssl function.

    Example:
        # Create wrapper once
        sm2_sign = GmsslCall(gmssl.sm2_sign, "sm2_sign")

        # Use it multiple times
        sm2_sign(byref(self), dgst, sig, byref(siglen))
        sm2_sign(byref(other), dgst2, sig2, byref(siglen2))

    Alternative usage with auto-naming:
        # Function name is extracted from the callable
        encrypt = GmsslCall(gmssl.sm2_encrypt)  # name = "sm2_encrypt"
        encrypt(byref(self), data, len(data), outbuf, byref(outlen))
    """

    def __init__(self, func, name=None):
        """
        Initialize the gmssl function wrapper.

        Args:
            func: The gmssl function to wrap
            name: Optional function name for error messages.
                  If not provided, attempts to extract from func.__name__
        """
        self.func = func
        # Try to extract name from function if not provided
        if name is None and hasattr(func, "__name__"):
            # Remove 'gmssl_' prefix if present
            name = func.__name__.replace("gmssl_", "")
        self.name = name or "gmssl_function"

    def __call__(self, *args, **kwargs):
        """
        Call the wrapped gmssl function and check for errors.

        Returns:
            The result from the gmssl function (typically 1 on success)

        Raises:
            NativeError: If the gmssl function returns a value != 1
        """
        result = self.func(*args, **kwargs)
        if result != 1:
            raise NativeError(f"{self.name} failed")
        return result


class _GmsslProxy:
    """
    Proxy object for gmssl library that auto-wraps functions with error checking.

    This eliminates the need to manually call raise_on_error or GmsslCall for every
    gmssl function call. Function names are automatically extracted from the attribute.

    Example:
        # Instead of:
        raise_on_error(gmssl.sm2_key_generate(byref(key)), "sm2_key_generate")

        # Simply write:
        checked.sm2_key_generate(byref(key))

        # The function name is automatically extracted and errors are checked
    """

    def __init__(self, lib):
        """
        Initialize proxy with the gmssl library.

        Args:
            lib: The loaded gmssl CDLL library instance
        """
        self._lib = lib

    def __getattr__(self, name):
        """
        Get gmssl function and wrap it with automatic error checking.

        Args:
            name: Function name (e.g., "sm2_key_generate")

        Returns:
            GmsslCall: Wrapped function with error checking
        """
        func = getattr(self._lib, name)
        return GmsslCall(func, name)


# Create a proxy instance for convenient access
checked = _GmsslProxy(gmssl)
