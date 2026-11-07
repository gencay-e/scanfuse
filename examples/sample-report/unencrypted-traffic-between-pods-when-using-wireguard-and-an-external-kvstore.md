# Unencrypted traffic between pods when using Wireguard and an external kvstore

**Severity**: Medium


**CVSS Score**: 6.1 (CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N)


**Source**: trivy



**Identifiers**: CVE-2024-25631, CWE-311


## Description
Cilium is a networking, observability, and security solution with an eBPF-based dataplane. For Cilium users who have enabled an external kvstore and Wireguard transparent encryption, traffic between pods in the affected cluster is not encrypted. This issue affects Cilium v1.14 before v1.14.7 and has been patched in Cilium v1.14.7. There is no workaround to this issue.


## Remediation
Update github.com/cilium/cilium from 1.14.5 to 1.14.7.



## References

- <https://avd.aquasec.com/nvd/cve-2024-25631>

- <https://docs.cilium.io/en/stable/installation/k8s-install-external-etcd/#when-do-i-need-to-use-a-kvstore>

- <https://docs.cilium.io/en/stable/security/network/encryption-wireguard/#encryption-wg>

- <https://github.com/cilium/cilium>

- <https://github.com/cilium/cilium/releases/tag/v1.14.7>

- <https://github.com/cilium/cilium/security/advisories/GHSA-x989-52fc-4vr4>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-25631>





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
