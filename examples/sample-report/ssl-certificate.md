# SSL certificate

**Severity**: Medium


**Source**: burp


**Port**: 443/tcp



**Affected**:

- 127.0.0.1 /




**Identifiers**: burp-type:16777472, CWE-295, CWE-326, CWE-327


## Description
The following problem was identified with the server's SSL certificate:

- The server's certificate is not valid for the server's hostname.

The server presented the following certificates:

Server certificate

Issued to:    *.example.com, example.com

Issued by:    Go Daddy Secure Certificate Authority - G2

Valid from:    Wed Jun 13 15:04:11 EDT 2018

Valid to:    Sat Jun 13 15:04:11 EDT 2020

Certificate chain #1

Issued to:    Go Daddy Secure Certificate Authority - G2

Issued by:    Go Daddy Root Certificate Authority - G2

Valid from:    Tue May 03 03:00:00 EDT 2011

Valid to:    Sat May 03 03:00:00 EDT 2031

Certificate chain #2

Issued to:    Go Daddy Root Certificate Authority - G2

Issued by:    Go Daddy Root Certificate Authority - G2

Valid from:    Mon Aug 31 20:00:00 EDT 2009

Valid to:    Thu Dec 31 18:59:59 EST 2037

Certificate chain #3

Issued to:    Go Daddy Root Certificate Authority - G2

Issued by:    Go Daddy Root Certificate Authority - G2

Valid from:    Mon Aug 31 20:00:00 EDT 2009

Valid to:    Thu Dec 31 18:59:59 EST 2037

SSL (or TLS) helps to protect the confidentiality and integrity of information in transit between the browser and server, and to provide authentication of the server's identity. To serve this purpose, the server must present an SSL certificate that is valid for the server's hostname, is issued by a trusted authority and is valid for the current date. If any one of these requirements is not met, SSL connections to the server will not provide the full protection for which SSL is designed.

It should be noted that various attacks exist against SSL in general, and in the context of HTTPS web connections in particular. It may be possible for a determined and suitably-positioned attacker to compromise SSL connections without user detection even when a valid SSL certificate is used.




## References

- <https://wiki.mozilla.org/Security/Server_Side_TLS>

- <https://cwe.mitre.org/data/definitions/295.html>

- <https://cwe.mitre.org/data/definitions/326.html>

- <https://cwe.mitre.org/data/definitions/327.html>





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
