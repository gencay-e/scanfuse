# Intermittent HTTP policy bypass

**Severity**: High


**CVSS Score**: 7.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N)


**Source**: trivy



**Identifiers**: CVE-2024-28248, CWE-693


## Description
Cilium is a networking, observability, and security solution with an eBPF-based dataplane. Starting in version 1.13.9 and prior to versions 1.13.13, 1.14.8, and 1.15.2, Cilium's HTTP policies are not consistently applied to all traffic in the scope of the policies, leading to HTTP traffic being incorrectly and intermittently forwarded when it should be dropped. This issue has been patched in Cilium 1.15.2, 1.14.8, and 1.13.13. There are no known workarounds for this issue.


## Remediation
Update github.com/cilium/cilium from 1.14.5 to 1.13.13, 1.14.8, 1.15.2.



## References

- <https://avd.aquasec.com/nvd/cve-2024-28248>

- <https://docs.cilium.io/en/stable/security/policy/language/#http>

- <https://github.com/cilium/cilium>

- <https://github.com/cilium/cilium/releases/tag/v1.13.13>

- <https://github.com/cilium/cilium/releases/tag/v1.14.8>

- <https://github.com/cilium/cilium/releases/tag/v1.15.2>

- <https://github.com/cilium/cilium/security/advisories/GHSA-68mj-9pjq-mc85>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-28248>





## Hosts

- unknown (.)


## Evidence

### target


```
go.mod
```

### package


```
Package: github.com/cilium/cilium
Installed: 1.14.5
```
