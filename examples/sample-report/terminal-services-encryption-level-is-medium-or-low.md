# Terminal Services Encryption Level is Medium or Low

**Severity**: Medium


**CVSS Score**: 4.3 (CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N)


**Source**: nessus


**Port**: 3389/tcp




**Identifiers**: nessus-plugin:57690


## Description
The remote host is using weak cryptography.

The remote Terminal Services service is not configured to use strong cryptography. 

Using weak cryptography with this service may allow an attacker to eavesdrop on the communications more easily and obtain screenshots and/or keystrokes.


## Remediation
Change RDP encryption level to one of :

3. High

4. FIPS Compliant




## Reported by


### nessus

**Severity**: Medium, **CVSS Score**: 4.3 (CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N)

The remote host is using weak cryptography.

The remote Terminal Services service is not configured to use strong cryptography. 

Using weak cryptography with this service may allow an attacker to eavesdrop on the communications more easily and obtain screenshots and/or keystrokes.


**Remediation**: Change RDP encryption level to one of :

3. High

4. FIPS Compliant




## Hosts

- 10.31.112.24 (qa3app04) - OS: Microsoft Windows Server 2008 R2 Standard Service Pack 1

- 10.31.112.23 (qa3app03) - OS: Microsoft Windows Server 2008 R2 Standard Service Pack 1


## Evidence

### port-info (nessus)


```
Port: 3389/tcp
Service: msrdp
```

### plugin-output (nessus)


```
The terminal services encryption level is set to :

2. Medium
```
