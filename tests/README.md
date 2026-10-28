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

The tests were run in October 2026 without legacy algorithms (MD5, RIPEMD-160, DES) and
without GOST. Note that the reported number of skipped tests is lower than the actual
number, because a single skipped test case may include multiple subtests.

- OpenSSL:
   - keys:     TOTAL OK: 73; OK (percent): 86; TOTAL FAILED: 0; TOTAL SKIPPED: 11
   - xmldsig:  TOTAL OK: 568; OK (percent): 94; TOTAL FAILED: 0; TOTAL SKIPPED: 33
   - xmlenc:   TOTAL OK: 778; OK (percent): 96; TOTAL FAILED: 0; TOTAL SKIPPED: 32

- NSS:
   - keys:     TOTAL OK: 63; OK (percent): 84; TOTAL FAILED: 0; TOTAL SKIPPED: 12
   - xmldsig:  TOTAL OK: 509; OK (percent): 93; TOTAL FAILED: 0; TOTAL SKIPPED: 35
   - xmlenc:   TOTAL OK: 694; OK (percent): 97; TOTAL FAILED: 0; TOTAL SKIPPED: 17

- GnuTLS:
   - keys:     TOTAL OK: 31; OK (percent): 72; TOTAL FAILED: 0; TOTAL SKIPPED: 12
   - xmldsig:  TOTAL OK: 506; OK (percent): 93; TOTAL FAILED: 0; TOTAL SKIPPED: 38
   - xmlenc:   TOTAL OK: 737; OK (percent): 95; TOTAL FAILED: 0; TOTAL SKIPPED: 36

- MSCng:
   - keys:     TOTAL OK: 24; OK (percent): 58; TOTAL FAILED: 0; TOTAL SKIPPED: 17
   - xmldsig:  TOTAL OK: 449; OK (percent): 91; TOTAL FAILED: 0; TOTAL SKIPPED: 43
   - xmlenc:   TOTAL OK: 612; OK (percent): 93; TOTAL FAILED: 0; TOTAL SKIPPED: 43

- MSCrypto:
   - keys:     TOTAL OK: 10; OK (percent): 29; TOTAL FAILED: 0; TOTAL SKIPPED: 24
   - xmldsig:  TOTAL OK: 269; OK (percent): 73; TOTAL FAILED: 0; TOTAL SKIPPED: 96
   - xmlenc:   TOTAL OK: 90; OK (percent): 25; TOTAL FAILED: 0; TOTAL SKIPPED: 268

- GCrypt:
   - keys:     TOTAL OK: 73; OK (percent): 86; TOTAL FAILED: 0; TOTAL SKIPPED: 11
   - xmldsig:  TOTAL OK: 211; OK (percent): 60; TOTAL FAILED: 0; TOTAL SKIPPED: 136
   - xmlenc:   TOTAL OK: 87; OK (percent): 23; TOTAL FAILED: 0; TOTAL SKIPPED: 276
