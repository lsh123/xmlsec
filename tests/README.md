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

## Recreate XML files on failures

To re-create or generate new XML files, use `XMLSEC_TEST_UPDATE_XML_ON_FAILURE` flag:

Example:

```
make check XMLSEC_TEST_UPDATE_XML_ON_FAILURE=yes
```


## Running tests after disabling features

If you disabled some features and tests are failing because there are too many
skipped tests, then you can disable this check by setting XMLSEC_TEST_IGNORE_PERCENT_SUCCESS
environment variable:


```
make check XMLSEC_TEST_IGNORE_PERCENT_SUCCESS=y
```

## Statistics

The tests are run without legacy algorithms (MD5, RIPEMD-160, DES) and without
GOST. Note that the reported number of skipped tests is lower than the actual
number, because a single skipped test case may include multiple subtests.

- OpenSSL:
  - xmldsig: TOTAL OK: 568; TOTAL FAILED: 0; TOTAL SKIPPED: 33
  - xmlenc:  TOTAL OK: 778; TOTAL FAILED: 0; TOTAL SKIPPED: 32

- NSS:
   - xmldsig: TOTAL OK: 506; TOTAL FAILED: 0; TOTAL SKIPPED: 38
   - xmlenc:  TOTAL OK: 737; TOTAL FAILED: 0; TOTAL SKIPPED: 36

- GnuTLS:
   - xmldsig: TOTAL OK: 509; TOTAL FAILED: 0; TOTAL SKIPPED: 35
   - xmlenc:  TOTAL OK: 694; TOTAL FAILED: 0; TOTAL SKIPPED: 17

- MSCng:
   - xmldsig: TOTAL OK: 251; TOTAL FAILED: 0; TOTAL SKIPPED: 20
   - xmlenc:  TOTAL OK: 518; TOTAL FAILED: 0; TOTAL SKIPPED: 1

- MSCrypto:
   - xmldsig: TOTAL OK: 191; TOTAL FAILED: 0; TOTAL SKIPPED: 57
   - xmlenc:  TOTAL OK: 132; TOTAL FAILED: 0; TOTAL SKIPPED: 181

- GCrypt:
   - xmldsig: TOTAL OK: 115; TOTAL FAILED: 0; TOTAL SKIPPED: 70
   - xmlenc:  TOTAL OK: 135; TOTAL FAILED: 0; TOTAL SKIPPED: 186
