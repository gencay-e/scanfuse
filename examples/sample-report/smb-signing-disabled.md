# SMB Signing Disabled

**Severity**: Medium


**CVSS Score**: 5.0 (CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N)


**Source**: nessus


**Port**: 445/tcp




**Identifiers**: nessus-plugin:57608


## Description
Signing is disabled on the remote SMB server.  This can allow man-in-the-middle attacks against the SMB server.


## Remediation
Enforce message signing in the host's configuration.  On Windows, this is found in the Local Security Policy.  On Samba, the setting is called 'server signing'.  See the 'see also' links for further details.



## References

- <http://support.microsoft.com/kb/887429>

- <http://www.nessus.org/u?74b80723>

- <http://www.samba.org/samba/docs/man/manpages-3/smb.conf.5.html>




## Reported by


### nessus

**Severity**: Medium, **CVSS Score**: 5.0 (CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N)

Signing is disabled on the remote SMB server.  This can allow man-in-the-middle attacks against the SMB server.


**Remediation**: Enforce message signing in the host's configuration.  On Windows, this is found in the Local Security Policy.  On Samba, the setting is called 'server signing'.  See the 'see also' links for further details.




## Hosts

- 10.31.112.24 (qa3app04) - OS: Microsoft Windows Server 2008 R2 Standard Service Pack 1

- 10.31.112.23 (qa3app03) - OS: Microsoft Windows Server 2008 R2 Standard Service Pack 1


## Evidence

### port-info (nessus)


```
Port: 445/tcp
Service: cifs
```
