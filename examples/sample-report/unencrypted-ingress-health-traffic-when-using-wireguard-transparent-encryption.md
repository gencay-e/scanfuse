# Unencrypted ingress/health traffic when using Wireguard transparent encryption

**Severity**: Medium


**CVSS Score**: 6.1 (CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N)


**Source**: trivy



**Identifiers**: CVE-2024-25630, CWE-311


## Description
Cilium is a networking, observability, and security solution with an eBPF-based dataplane. For Cilium users who are using CRDs to store Cilium state (the default configuration) and Wireguard transparent encryption, traffic to/from the Ingress and health endpoints is not encrypted. This issue affects Cilium v1.14 before v1.14.7 and has been patched in Cilium v1.14.7. There is no workaround to this issue.


## Remediation
Update github.com/cilium/cilium from 1.14.5 to 1.14.7.



## References

- <https://avd.aquasec.com/nvd/cve-2024-25630>

- <https://docs.cilium.io/en/stable/security/network/encryption-wireguard/#encryption-wg>

- <https://github.com/cilium/cilium>

- <https://github.com/cilium/cilium/releases/tag/v1.14.7>

- <https://github.com/cilium/cilium/security/advisories/GHSA-7496-fgv9-xw82>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-25630>





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
