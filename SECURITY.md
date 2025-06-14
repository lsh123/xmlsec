# Security Policy

## Supported Versions

The XMLSec library WILL provide security updates / fixes for the released versions for 5 years since [the day of the release](https://www.aleksey.com/xmlsec/news.html).
After 5 years, the support MIGHT be provided on case-by-case basis.

### 1.3.x (master)

| Component/Version | Version   | Release date       | Full Support          | Security Support    |
| ------------------|-----------| -------------------|-----------------------|---------------------|
| xmlsec-core       | >= 1.3.0  | April 12, 2023     | :white_check_mark:    | :white_check_mark:  |
| xmlsec-openssl    | >= 1.3.0  | April 12, 2023     | :white_check_mark:    | :white_check_mark:  |
| xmlsec-nss        | >= 1.3.0  | April 12, 2023     | :white_check_mark:    | :white_check_mark:  |
| xmlsec-gnutls     | >= 1.3.0  | April 12, 2023     | :white_check_mark:    | :white_check_mark:  |
| xmlsec-mscng      | >= 1.3.0  | April 12, 2023     | :white_check_mark:    | :white_check_mark:  |
| xmlsec-gcrypt     | >= 1.3.0  | April 12, 2023     | :x:                   | :white_check_mark:  |
| xmlsec-mscrypto   | >= 1.3.0  | April 12, 2023     | :x:                   | :white_check_mark:  |

### 1.2.x (mainanance mode from April 2023, planned End-Of-Life in April 2028)

| Component/Version | Version   | Release date       | Full Support          | Security Support    |
| ------------------|-----------| -------------------|-----------------------|---------------------|
| all               | >= 1.2.38 | July 5, 2023       | :x:                   | :white_check_mark:  |
| all               | < 1.2.38  | October 15, 2019   | :x:                   | :x:                 |

## Reporting a Vulnerability

Please use [GitHub private vulnerability reporting tool](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
to report any security issues or vulnerabilities.
