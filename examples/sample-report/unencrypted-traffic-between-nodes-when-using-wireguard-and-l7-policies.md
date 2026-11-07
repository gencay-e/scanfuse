# Unencrypted traffic between nodes when using WireGuard and L7 policies

**Severity**: Medium


**CVSS Score**: 6.1 (CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N)


**Source**: trivy



**Identifiers**: CVE-2024-28250, CWE-311


## Description
Cilium is a networking, observability, and security solution with an eBPF-based dataplane. Starting in version 1.14.0 and prior to versions 1.14.8 and 1.15.2, In Cilium clusters with WireGuard enabled and traffic matching Layer 7 policies Wireguard-eligible traffic that is sent between a node's Envoy proxy and pods on other nodes is sent unencrypted and Wireguard-eligible traffic that is sent between a node's DNS proxy and pods on other nodes is sent unencrypted. This issue has been resolved in Cilium 1.14.8 and 1.15.2 in in native routing mode (`routingMode=native`) and in Cilium 1.14.4 in tunneling mode (`routingMode=tunnel`). Not that in tunneling mode, `encryption.wireguard.encapsulate` must be set to `true`. There is no known workaround for this issue.


## Remediation
Update github.com/cilium/cilium from 1.14.5 to 1.14.8, 1.15.2.



## References

- <https://avd.aquasec.com/nvd/cve-2024-28250>

- <https://github.com/cilium/cilium>

- <https://github.com/cilium/cilium/releases/tag/v1.13.13>

- <https://github.com/cilium/cilium/releases/tag/v1.14.8>

- <https://github.com/cilium/cilium/releases/tag/v1.15.2>

- <https://github.com/cilium/cilium/security/advisories/GHSA-v6q2-4qr3-5cw6>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-28250>





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
