# Cilium's CIDR deny policies may not take effect when a more narrow CIDR allow is present

**Severity**: Medium


**CVSS Score**: 4.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N)


**Source**: trivy



**Identifiers**: CVE-2024-47825, CWE-276


## Description
Cilium is a networking, observability, and security solution with an eBPF-based dataplane. Starting in version 1.14.0 and prior to versions 1.14.16 and 1.15.10, a policy rule denying a prefix that is broader than `/32` may be ignored if there is a policy rule referencing a more narrow prefix (`CIDRSet` or `toFQDN`) and this narrower policy rule specifies either `enableDefaultDeny: false` or `- toEntities: all`. Note that a rule specifying `toEntities: world` or `toEntities: 0.0.0.0/0` is insufficient, it must be to entity `all`.This issue has been patched in Cilium v1.14.16 and v1.15.10. As this issue only affects policies using `enableDefaultDeny: false` or that set `toEntities` to `all`, some workarounds are available. For users with policies using `enableDefaultDeny: false`, remove this configuration option and explicitly define any allow rules required. For users with egress policies that explicitly specify `toEntities: all`, use `toEntities: world`.


## Remediation
Update github.com/cilium/cilium from 1.14.5 to 1.15.10, 1.14.16.



## References

- <https://avd.aquasec.com/nvd/cve-2024-47825>

- <https://github.com/cilium/cilium>

- <https://github.com/cilium/cilium/commit/02d28d9ac9afcaddd301fae6fb4d6cda8c2d0c45>

- <https://github.com/cilium/cilium/commit/9c01afb5646af3f0c696421a410dc66c513b6524>

- <https://github.com/cilium/cilium/security/advisories/GHSA-3wwx-63fv-pfq6>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-47825>





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
