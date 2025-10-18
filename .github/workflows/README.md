# GitHub Actions Workflows

## Overview

This repository has two main workflows:

1. **Build GmSSL Libraries** (`build-gmssl-libs.yml`) - Updates bundled GmSSL libraries
2. **Release to GitHub** (`release.yml`) - Publishes Python packages to GitHub Releases

---

## Build GmSSL Libraries

### Purpose

The `build-gmssl-libs.yml` workflow builds GmSSL dynamic libraries for multiple platforms and creates a PR to update the bundled libraries in `src/gmssl/_libs/`.

### Supported Platforms

- **Linux**: x86_64, aarch64 (`libgmssl.so.3`)
  - Built with manylinux_2_28 (glibc 2.28+)
  - Compatible with Ubuntu 20.04+, Debian 11+, RHEL 8+, etc.
- **macOS**: Universal binary arm64 + x86_64 (`libgmssl.3.dylib`)
  - Compatible with macOS 11.0+
- **Windows**: x86_64 (`gmssl.dll`)
  - Compatible with Windows 10+

### How to Use

1. Go to **Actions** tab in GitHub
2. Select **Build GmSSL Libraries** workflow
3. Click **Run workflow**
4. Enter parameters:
   - **GmSSL version**: e.g., `3.1.1` (default)
   - **GmSSL repository**: e.g., `https://github.com/guanzhi/GmSSL.git` (default)
5. Click **Run workflow** button

### What Happens

1. **Build Stage**: Compiles GmSSL for each platform in parallel
   - Linux x86_64: manylinux_2_28 container (glibc 2.28) - wide compatibility
   - Linux aarch64: manylinux_2_28 container (glibc 2.28) - wide compatibility
   - macOS arm64: macOS latest (M1/M2)
   - macOS x86_64: macOS 13 (Intel)
   - Windows x86_64: Windows latest with MSVC

2. **Artifact Stage**: Uploads compiled libraries as artifacts
   - Retention: 7 days
   - Can be downloaded manually if needed

3. **Test Stage**: Automatically tests libraries on multiple platforms
   - **Linux**: Tests with Python 3.8, 3.9, 3.10, 3.11, 3.12
   - **macOS**: Tests with Python 3.12 (universal binary)
   - **Windows**: Tests with Python 3.12
   - Runs full test suite (`pytest tests/ -v`)
   - Verifies library loading and version info
   - **Fail-fast disabled**: All combinations tested even if one fails

4. **PR Stage**: Creates a pull request with updated libraries (only if tests pass)
   - Branch: `update-gmssl-libs-{version}`
   - Includes all platform libraries
   - macOS: Creates universal binary (arm64 + x86_64)
   - **All tests must pass** before PR is created

### Testing the PR

**Automated Testing**: The workflow automatically tests all libraries before creating the PR. You can review test results in the Actions tab.

**Manual Testing** (optional): If you want to test locally:

```bash
# Clone the PR branch
git fetch origin update-gmssl-libs-{version}
git checkout update-gmssl-libs-{version}

# Run tests (library is self-contained, no environment setup needed)
pytest tests/ -v

# Build wheel and verify library is included
python -m build --wheel
unzip -l dist/gmssl_python-*.whl | grep -E "(\.dylib|\.so|\.dll)"
```

**Test Coverage**:
- ✅ Linux x86_64: Python 3.8, 3.9, 3.10, 3.11, 3.12
- ✅ macOS universal: Python 3.12
- ✅ Windows x86_64: Python 3.12
- ✅ All 19 test cases from `tests/test_gmssl.py`

### Manual Library Update

If you need to update libraries manually:

1. Build GmSSL on your platform:
   ```bash
   git clone https://github.com/guanzhi/GmSSL.git
   cd GmSSL
   mkdir build && cd build
   cmake .. -DCMAKE_BUILD_TYPE=Release
   make -j$(nproc)
   ```

2. Copy library to package:
   ```bash
   # Linux
   cp bin/libgmssl.so.3 ../GmSSL-Python/src/gmssl/_libs/

   # macOS
   cp bin/libgmssl.3.dylib ../GmSSL-Python/src/gmssl/_libs/

   # Windows
   cp bin/Release/gmssl.dll ../GmSSL-Python/src/gmssl/_libs/
   ```

3. Verify and commit:
   ```bash
   cd ../GmSSL-Python
   git add src/gmssl/_libs/
   git commit -m "chore: update bundled GmSSL library for {platform}"
   ```

### Troubleshooting

**Q: Workflow fails on Windows build**
- Check if GmSSL CMake configuration supports Windows
- Verify MSVC toolchain is properly set up
- Check GmSSL version compatibility

**Q: macOS universal binary creation fails**
- Fallback: Uses arm64 library only
- Can manually create universal binary with `lipo` command

**Q: Library dependencies missing**
- GmSSL should only depend on system libraries
- Check with `ldd` (Linux), `otool -L` (macOS), or `dumpbin /dependents` (Windows)

**Q: Tests fail on specific platform**
- Check the Actions tab for detailed test output
- Common issues:
  - Library not found: Verify artifact download step
  - Import errors: Check Python version compatibility
  - Test failures: May indicate library build issues

### Debug Information

The workflow includes extensive debug output to help diagnose issues:

**Library verification:**
- File type and architecture information
- Symbol table checks (especially SM9 functions: `sm9_sign_*`)
- Dependencies verification (ldd/otool)
- Libraries are NOT stripped (preserving all symbols for debugging)

**Test debugging:**
- Verbose test output with `-v -s --tb=short`
- Separate SM9 test run with full traceback (`--tb=long`)
- Tests continue even on failure (`continue-on-error: true`)
- Shows loaded library path and version

**Known Issues:**
- SM9 tests may fail in CI environments (under investigation)
- If SM9 tests fail, check the debug output for:
  - Symbol table contains `sm9_sign_*` functions
  - Library size (unstripped libraries are larger)
  - Python version and platform combination
  - Loaded library path matches expected bundled library
- PR will not be created if any tests fail

**Q: Want to skip tests and create PR anyway**
- Not recommended, but you can:
  - Manually download artifacts from the workflow run
  - Create PR manually following the steps in "Manual Library Update"

### License

GmSSL is licensed under Apache-2.0, same as this project.
Redistribution is permitted under the terms of the Apache License 2.0.

---

## Release to GitHub

### Purpose

The `release.yml` workflow builds Python packages (wheel and sdist), tests them on multiple platforms, and creates a GitHub Release with the packages as downloadable assets.

### Trigger Methods

**Method 1: Push a version tag (Recommended)**
```bash
# Update version in pyproject.toml first
# Then create and push a tag
git tag v2.2.3
git push origin v2.2.3
```

**Method 2: Manual trigger**
1. Go to **Actions** tab in GitHub
2. Select **Release to GitHub** workflow
3. Click **Run workflow**
4. Select branch (usually `main`)
5. Click **Run workflow** button

### What Happens

1. **Build Stage**: Creates Python packages
   - Builds universal wheel (`gmssl_python-{version}-py3-none-any.whl`)
   - Builds source distribution (`gmssl_python-{version}.tar.gz`)
   - Verifies package includes bundled libraries
   - Validates package metadata with `twine check`

2. **Test Stage**: Tests packages on multiple platforms
   - **Platforms**: Linux, macOS, Windows
   - **Python versions**: 3.8, 3.12
   - Installs wheel and runs full test suite
   - Verifies library loading and version info

3. **Release Stage**: Creates GitHub Release (only if all tests pass)
   - Creates release with version tag
   - Generates release notes automatically
   - Uploads wheel and sdist as release assets
   - **Public release** - users can download packages directly

### Version Management

**Important**: The version in `pyproject.toml` must match the git tag.

```toml
# pyproject.toml
[project]
version = "2.2.3"  # Must match tag v2.2.3
```

The workflow will verify version consistency and fail if they don't match.

### Release Notes

Release notes are auto-generated and include:
- Installation instructions
- What's included in the package
- Package file descriptions
- Link to documentation

You can customize the release notes after creation if needed.

### After Release

Users can install the package in three ways:

**1. From PyPI (if you publish there)**
```bash
pip install gmssl-python==2.2.3
```

**2. From GitHub Release**
```bash
# Download wheel from release page, then:
pip install gmssl_python-2.2.3-py3-none-any.whl
```

**3. From source**
```bash
pip install https://github.com/GmSSL/GmSSL-Python/archive/refs/tags/v2.2.3.tar.gz
```

### Publishing to PyPI

This workflow only creates GitHub Releases. To publish to PyPI:

```bash
# Download packages from GitHub Release or build locally
python -m build

# Upload to PyPI
twine upload dist/*
```

Or create a separate workflow for PyPI publishing (recommended).

### Troubleshooting

**Q: Workflow fails with "Version mismatch"**
- Make sure `pyproject.toml` version matches the git tag
- Example: Tag `v2.2.3` requires `version = "2.2.3"` in pyproject.toml

**Q: Tests fail on specific platform**
- Check the Actions tab for detailed test output
- Common issues: missing libraries, import errors
- Fix the issue and re-run the workflow or push a new tag

**Q: Want to delete a release**
- Go to Releases page
- Click on the release
- Click "Delete this release"
- Optionally delete the tag: `git push --delete origin v2.2.3`

**Q: Want to update a release**
- You can edit release notes and re-upload files manually
- Or delete the release and tag, then re-run the workflow

### Best Practices

1. **Test before releasing**
   - Run tests locally: `pytest tests/ -v`
   - Build and test wheel locally: `python -m build && pip install dist/*.whl`

2. **Version bumping**
   - Update version in `pyproject.toml`
   - Update CHANGELOG or release notes
   - Commit changes before tagging

3. **Semantic versioning**
   - Use semantic versioning: `MAJOR.MINOR.PATCH`
   - Example: `2.2.3` → `2.2.4` (patch), `2.3.0` (minor), `3.0.0` (major)

4. **Tag naming**
   - Always prefix with `v`: `v2.2.3`
   - Use annotated tags: `git tag -a v2.2.3 -m "Release version 2.2.3"`
