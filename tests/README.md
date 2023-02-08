# XMLSec Library: Unit Tests

## Running a specific test

If a test fails, it's possible to re-run just that specific test for that
specific backend using:

```
make check-crypto-$backend XMLSEC_TEST_NAME="$name"
```

where `$name` is the key name for key tests, and a file name otherwise.

Example:

```
make check-crypto-nss XMLSEC_TEST_NAME="enveloping-sha256-rsa-sha256-relationship"
```

## Reproducible output

It is also possible to have reproducible output, filtering out timestamps. This
is useful to see the output before and after a change to understand its impact.

Example:

```
make check XMLSEC_TEST_REPRODUCIBLE=y
```

## Running tests after disabling features

If you disabled some features and tests are failing because there are too many
skipped tests, then you can disable this check by setting XMLSEC_TEST_IGNORE_PERCENT_SUCCESS
environment variable:


```
make check XMLSEC_TEST_IGNORE_PERCENT_SUCCESS=y
```

## Statitistics

The tests are run with legacy algorithms enabled but without GOST. Note that skipped
tests report is lower than actual because when a test case is skipped, it might include
multiple subtests (that will be counted in the total successful number).

- OpenSSL:
  - xmldsig: TOTAL OK: 293; TOTAL FAILED: 0; TOTAL SKIPPED: 3
  - xmlenc:  TOTAL OK: 590; TOTAL FAILED: 0; TOTAL SKIPPED: 0

- NSS:
   - xmldsig: TOTAL OK: 268; TOTAL FAILED: 0; TOTAL SKIPPED: 11
   - xmlenc:  TOTAL OK: 578; TOTAL FAILED: 0; TOTAL SKIPPED: 4

- GnuTLS:
   - xmldsig: TOTAL OK: 238; TOTAL FAILED: 0; TOTAL SKIPPED: 26
   - xmlenc:  TOTAL OK: 482; TOTAL FAILED: 0; TOTAL SKIPPED: 36

- MSCng:
   - xmldsig: TOTAL OK: 251; TOTAL FAILED: 0; TOTAL SKIPPED: 20
   - xmlenc:  TOTAL OK: 518; TOTAL FAILED: 0; TOTAL SKIPPED: 1

- MSCrypto:
   - xmldsig: TOTAL OK: 191; TOTAL FAILED: 0; TOTAL SKIPPED: 57
   - xmlenc:  TOTAL OK: 132; TOTAL FAILED: 0; TOTAL SKIPPED: 181

- GCrypt:
   - xmldsig: TOTAL OK: 115; TOTAL FAILED: 0; TOTAL SKIPPED: 70
   - xmlenc:  TOTAL OK: 135; TOTAL FAILED: 0; TOTAL SKIPPED: 186
