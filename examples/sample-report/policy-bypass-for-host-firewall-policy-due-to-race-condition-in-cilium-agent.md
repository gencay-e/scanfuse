# Policy bypass for Host Firewall policy due to race condition in Cilium agent

**Severity**: Medium


**CVSS Score**: 6.8 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N)


**Source**: trivy



**Identifiers**: CVE-2024-42488, CWE-362


## Description
Cilium is a networking, observability, and security solution with an eBPF-based dataplane. Prior to versions 1.14.14 and 1.15.8, a race condition in the Cilium agent can cause the agent to ignore labels that should be applied to a node. This could in turn cause CiliumClusterwideNetworkPolicies intended for nodes with the ignored label to not apply, leading to policy bypass. This issue has been patched in Cilium v1.14.14 and v1.15.8 As the underlying issue depends on a race condition, users unable to upgrade can restart the Cilium agent on affected nodes until the affected policies are confirmed to be working as expected.


## Remediation
Update github.com/cilium/cilium from 1.14.5 to 1.14.14, 1.15.8.



## References

- <https://avd.aquasec.com/nvd/cve-2024-42488>

- <https://github.com/cilium/cilium>

- <https://github.com/cilium/cilium/commit/7877db09b3f34d3081a1d66459b8fa6603dc3d30>

- <https://github.com/cilium/cilium/commit/aa44dd148a9be95e07782e4f990e61678ef0abf8>

- <https://github.com/cilium/cilium/commit/f81a1ee0cfdec928980db8640def984b2eeaa134>

- <https://github.com/cilium/cilium/pull/33511>

- <https://github.com/cilium/cilium/security/advisories/GHSA-q7w8-72mr-vpgw>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-42488>





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
