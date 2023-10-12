# GmSSL-Python Develop

## Publish to PiPy

See https://packaging.python.org/distributing/

1. Update version in `gmssl.py`
2. Update version in `pyproject.toml`
3. Build package, run `python3 -m build`
4. Publish package to PiPy, run `python3 -m twine upload dist/*`


