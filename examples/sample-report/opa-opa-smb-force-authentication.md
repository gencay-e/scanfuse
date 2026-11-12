# opa: OPA SMB Force-Authentication

**Severity**: Medium


**CVSS Score**: 7.3 (CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H)


**Source**: trivy




**Identifiers**: CVE-2024-8260, CWE-294


## Description
A SMB force-authentication vulnerability exists in all versions of OPA for Windows prior to v0.68.0. The vulnerability exists because of improper input validation, allowing a user to pass an arbitrary SMB share instead of a Rego file as an argument to OPA CLI or to one of the OPA Go library’s functions.


## Remediation
Update github.com/open-policy-agent/opa from 0.60.0 to 0.68.0.



## References

- <https://avd.aquasec.com/nvd/cve-2024-8260>

- <https://access.redhat.com/security/cve/CVE-2024-8260>

- <https://github.com/open-policy-agent/opa>

- <https://github.com/open-policy-agent/opa/commit/10f4d553e6bb6ae9c69611ecdd9a77dda857070e>

- <https://github.com/open-policy-agent/opa/releases/tag/v0.68.0>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-8260>

- <https://pkg.go.dev/vuln/GO-2024-3141>

- <https://www.cve.org/CVERecord?id=CVE-2024-8260>

- <https://www.tenable.com/security/research/tra-2024-36>





## Hosts

- unknown (.)


## Evidence

### target


```
go.mod
```

### package


```
Package: github.com/open-policy-agent/opa
Installed: 0.60.0
```
