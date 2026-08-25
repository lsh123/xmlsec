# XMLSec Agent Guidelines

This file defines default instructions for AI agents working in this repository.

## Project Context

- Project name: XML Security Library (xmlsec).
- Purpose: C implementation of XML Signature and XML Encryption standards.
- Main deliverables:
  - Core xmlsec library.
  - Crypto backends (OpenSSL, NSS, GnuTLS, MSCng, MSCrypto, GCrypt).
  - `xmlsec1` command-line tool and unit/fuzz test executables.
- Primary docs:
  - `README.md`
  - `docs/md/tutorial/install.md`
  - `docs/md/tutorial/compiling-and-linking.md`
  - `tests/README.md`

## Tech Stack

- Language: C (core library, apps, tests).
- Build systems:
  - Linux/Unix/macOS/MinGW/Cygwin: Autotools (`autoreconf`, `configure`, `make`).
  - Windows MSVC: MSVC + NMAKE via `win32/configure.ps1` and `win32/Makefile.msvc`.
- Scripting: POSIX shell scripts (`tests/*.sh`, scripts in `scripts/`) and PowerShell (`win32/configure.ps1`).
- Key dependencies:
  - LibXML2 (required)
  - LibXSLT (optional)
  - One or more crypto libraries (OpenSSL/LibreSSL/BoringSSL, NSS+NSPR, GnuTLS, MSCng, etc.)

## Core Components And Folder Structure

- `src/`: core library implementation.
  - `src/openssl/`, `src/nss/`, `src/gnutls/`, `src/mscng/`, `src/mscrypto/`, `src/gcrypt/`: crypto backend implementations.
- `include/xmlsec/`: public headers.
- `apps/`: CLI tool and unit/fuzz harness sources.
- `tests/`: integration test scripts, test vectors, and key material.
- `examples/`: sample apps for sign/verify/encrypt/decrypt flows.
- `docs/`: markdown docs, API docs sources, generated docs assets.
- `win32/`: Windows-specific build scripts and makefiles.
- `scripts/`: release/build helper scripts.

## Build And Test Instructions

### Linux/Unix/macOS/MinGW/Cygwin

Use these commands when working from this Git checkout:

```sh
autoreconf -i -f
./configure [options]
make
make check
```

Common targeted test commands:

```sh
# Run one backend only
make check-crypto-openssl

# Re-run one specific failing test name
make check-crypto-nss XMLSEC_TEST_NAME="enveloping-sha256-rsa-sha256-relationship"

# Deterministic output (less timestamp noise)
make check XMLSEC_TEST_REPRODUCIBLE=y

# Update expected XML files when intentionally changing outputs
make check XMLSEC_TEST_UPDATE_XML_ON_FAILURE=yes
```

Notes:
- Some tests may require Internet access for external resources.
- If feature-disabled builds reduce pass percentage, use:

```sh
make check XMLSEC_TEST_IGNORE_PERCENT_SUCCESS=y
```

### Windows (MSVC + NMAKE)

Use a Visual Studio Developer Command Prompt (or a shell initialized with `vcvars*.bat`).

```powershell
cd win32
powershell -ExecutionPolicy Bypass -File configure.ps1 [options]
nmake
nmake check
nmake install
```

Useful options help:

```powershell
powershell -ExecutionPolicy Bypass -File configure.ps1 help
```

Windows notes:
- Do not build in paths that contain spaces.
- Copy dependencies to the output directory (see `mycfg.bat` for details)
- `nmake check` executes test shell scripts, so a POSIX `sh` must be available on PATH.
- If debug builds hit `C1041`/`vc140.pdb` contention, remove `win32\vc140.pdb` and retry with `CL=/FS`.

## Boundaries And Rules

- DO: Ask the user when in doubt
   - If there are multiple options and no clear "best option" - ask the user
- DO: Prefer minimal, focused changes that preserve existing APIs and behavior unless the task explicitly asks for behavior changes.
   - Flag any changes that would break ABI and / or API compatibility
   - Do not create new public APIs unless explicitly asked (prefer static in-file functions or private functions defined inside headers in the src/ folder)
- DO: Treat security-sensitive defaults as intentional:
  - Do not re-enable legacy algorithms/features by default.
  - Do not weaken verification behavior or certificate checks without explicit requirement and documentation update.
- DO: Keep performance in mind:
  - Flag any changes that would impact performance.
- DO: Keep platform parity in mind:
  - For cross-platform features/fixes, update both Autotools and Windows build paths where applicable.
- DO: Check all function return values 
  - Sometimes older versions of the dependency library don't return a value and in this case #ifdef's should be used to differentiate old vs new library code paths.
- DO: When touching tests:
  - Run the narrowest relevant test target first, then broader suites.
  - Call out tests that depend on network availability.
- DO: Preserve project coding style:
  - Follow existing naming, macro patterns, and formatting in touched files.
- DO: Keep documentation in sync for user-visible build/test/configuration changes.
  - The documentation for API is generated from source code comments.
- DO: All comments, error messages, etc should follow proper grammar.
  - Avoid copy / paste errors.
- DO NOT introduce unrelated refactors
  - Focus on the task, if any additional issues are discovered -- note them in the final report or add comments to the source code.
- DO NOT Edit generated artifacts unless explicitly requested:
  - Prefer editing source inputs such as `configure.ac`, `Makefile.am`, and source files instead of generated `configure`/`Makefile.in` outputs.
- DO NOT Introduce long complex functions
  - Prefer small functions when possible
- DO NOT Modify existing tests automatically
  - Ask the user if the existing test should be changed 

## Useful information
- xmlSecAssert, xmlSecAssert2, etc are executed in both release and debug builds.
- Functions are documented in .c files and headers are minimal. 


