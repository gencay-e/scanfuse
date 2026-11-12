# \[SSL Scanner\] POODLE (SSLv3)

**Severity**: High


**Source**: burp


**Port**: 443/tcp



**Location**: /



**Identifiers**: burp-type:134217728


## Description
The host is vulnerable to the POODLE attack which affects every website that supports SSLv3. The POODLE attack allows an attacker to extract the plaintext message of a targeted part of a request. There is also a variant of the attack that affects more recent versions of TLS. (Requires external tools) (CVE-2014-3566)


## Remediation
If OpenSSL is used, update to version 1.0.1j or higher. Otherwise, update the web server and client to the latest version. Check for TLS_FALLBACK_SCSV support on the server to prevent downgrade attack and help mitigate this issue (SSL Scanner will report if there is no support for TLS_FALLBACK_SCSV). Also, SSLv3 should never be offered.

- For Internet Explorer 6, there is an option to disable SSLv3 and enable TLS1.0. However, it is only advisable as a workaround.





## Hosts

- 127.0.0.1 (https://127.0.0.1)


## Evidence

### path


```
/
```

### burp-details


```
Confidence: Tentative
```
