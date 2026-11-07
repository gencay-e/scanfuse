# \[SSL Scanner\] Offer SSLv3

**Severity**: High


**Source**: burp



**Identifiers**: burp-type:134217728


## Description
The host uses SSLv3, which is a weak encryption scheme broken by the POODLE attack. (CWE-326)


## Remediation
SSLv3 should never be enabled on production systems.





## Hosts

- 127.0.0.1 (https://127.0.0.1)


## Evidence

### path


```
/
```

### burp-details


```
Confidence: Certain
```
