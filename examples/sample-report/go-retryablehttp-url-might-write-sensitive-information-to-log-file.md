# go-retryablehttp: url might write sensitive information to log file

**Severity**: Medium


**CVSS Score**: 5.5 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)


**Source**: trivy



**Identifiers**: CVE-2024-6104, CWE-532


## Description
go-retryablehttp prior to 0.7.7 did not sanitize urls when writing them to its log file. This could lead to go-retryablehttp writing sensitive HTTP basic auth credentials to its log file. This vulnerability, CVE-2024-6104, was fixed in go-retryablehttp 0.7.7.


## Remediation
Update github.com/hashicorp/go-retryablehttp from 0.7.5 to 0.7.7.



## References

- <https://avd.aquasec.com/nvd/cve-2024-6104>

- <https://access.redhat.com/errata/RHSA-2024:9115>

- <https://access.redhat.com/security/cve/CVE-2024-6104>

- <https://bugzilla.redhat.com/2279814>

- <https://bugzilla.redhat.com/2292668>

- <https://bugzilla.redhat.com/2292787>

- <https://bugzilla.redhat.com/2294000>

- <https://bugzilla.redhat.com/2295310>

- <https://discuss.hashicorp.com/c/security>

- <https://discuss.hashicorp.com/t/hcsec-2024-12-go-retryablehttp-can-leak-basic-auth-credentials-to-log-files/68027>

- <https://errata.almalinux.org/9/ALSA-2024-9115.html>

- <https://github.com/advisories/GHSA-v6v8-xj6m-xwqh>

- <https://github.com/hashicorp/go-retryablehttp>

- <https://github.com/hashicorp/go-retryablehttp/commit/a99f07beb3c5faaa0a283617e6eb6bcf25f5049a>

- <https://linux.oracle.com/cve/CVE-2024-6104.html>

- <https://linux.oracle.com/errata/ELSA-2024-9115.html>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-6104>

- <https://www.cve.org/CVERecord?id=CVE-2024-6104>





## Hosts

- unknown (.)


## Evidence

### target


```
go.mod
```

### package


```
Package: github.com/hashicorp/go-retryablehttp
Installed: 0.7.5
```
