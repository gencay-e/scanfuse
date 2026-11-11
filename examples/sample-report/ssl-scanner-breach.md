# \[SSL Scanner\] BREACH

**Severity**: Medium


**Source**: burp


**Port**: 443/tcp



**Identifiers**: burp-type:134217728


## Description
This server offers HTTP compression which can lead to chosen plaintext attack similar to CRIME where the attack can recover secret cookie such as authentication cookie using the size of compressed request/response. This issue can be ignored if there is no secret in the page or static pages.


## Remediation
Disable HTTP compression on the server or ignored if there is no secret in the page.





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
