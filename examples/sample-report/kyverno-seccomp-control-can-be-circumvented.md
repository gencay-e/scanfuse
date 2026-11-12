# kyverno seccomp control can be circumvented

**Severity**: Medium


**CVSS Score**: 8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)


**Source**: trivy




**Identifiers**: CVE-2023-33191, CWE-284


## Description
Kyverno is a policy engine designed for Kubernetes. Kyverno seccomp control can be circumvented. Users of the podSecurity `validate.podSecurity` subrule in Kyverno 1.9.2 and 1.9.3 are vulnerable. This issue was patched in version 1.9.4.


## Remediation
Update github.com/kyverno/kyverno from 1.9.2 to 1.9.4.



## References

- <https://avd.aquasec.com/nvd/cve-2023-33191>

- <https://github.com/kyverno/kyverno>

- <https://github.com/kyverno/kyverno/pull/7263>

- <https://github.com/kyverno/kyverno/releases/tag/v1.9.4>

- <https://github.com/kyverno/kyverno/security/advisories/GHSA-33hq-f2mf-jm3c>

- <https://nvd.nist.gov/vuln/detail/CVE-2023-33191>





## Hosts

- unknown (.)


## Evidence

### target


```
go.mod
```

### package


```
Package: github.com/kyverno/kyverno
Installed: 1.9.2
```
