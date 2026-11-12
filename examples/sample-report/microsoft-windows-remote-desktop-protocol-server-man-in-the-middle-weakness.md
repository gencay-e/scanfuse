# Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness

**Severity**: Medium


**CVSS Score**: 5.1 (CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P)


**Source**: nessus


**Port**: 3389/tcp




**Identifiers**: nessus-plugin:18405, CVE-2005-1794


## Description
It may be possible to get access to the remote host.

The remote version of the Remote Desktop Protocol Server (Terminal Service) is vulnerable to a man-in-the-middle (MiTM) attack. The RDP client makes no effort to validate the identity of the server when setting up encryption. An attacker with the ability to intercept traffic from the RDP server can establish encryption with the client and server without being detected. A MiTM attack of this nature would allow the attacker to obtain any sensitive information transmitted, including authentication credentials.

This flaw exists because the RDP server stores a hardcoded RSA private key in the mstlsapi.dll library. Any local user with access to this file (on any Windows system) can retrieve the key and use it for this attack.


## Remediation
- Force the use of SSL as a transport layer for this service if supported, or/and
- Select the 'Allow connections only from computers running Remote Desktop with Network Level Authentication' setting if it is available.



## References

- <http://www.oxid.it/downloads/rdp-gbu.pdf>

- <http://www.nessus.org/u?e2628096>

- <http://technet.microsoft.com/en-us/library/cc782610.aspx>




## Reported by


### nessus

**Severity**: Medium, **CVSS Score**: 5.1 (CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P)

It may be possible to get access to the remote host.

The remote version of the Remote Desktop Protocol Server (Terminal Service) is vulnerable to a man-in-the-middle (MiTM) attack. The RDP client makes no effort to validate the identity of the server when setting up encryption. An attacker with the ability to intercept traffic from the RDP server can establish encryption with the client and server without being detected. A MiTM attack of this nature would allow the attacker to obtain any sensitive information transmitted, including authentication credentials.

This flaw exists because the RDP server stores a hardcoded RSA private key in the mstlsapi.dll library. Any local user with access to this file (on any Windows system) can retrieve the key and use it for this attack.


**Remediation**: - Force the use of SSL as a transport layer for this service if supported, or/and
- Select the 'Allow connections only from computers running Remote Desktop with Network Level Authentication' setting if it is available.




## Hosts

- 10.31.112.24 (qa3app04) - OS: Microsoft Windows Server 2008 R2 Standard Service Pack 1

- 10.31.112.23 (qa3app03) - OS: Microsoft Windows Server 2008 R2 Standard Service Pack 1


## Evidence

### port-info (nessus)


```
Port: 3389/tcp
Service: msrdp
```
