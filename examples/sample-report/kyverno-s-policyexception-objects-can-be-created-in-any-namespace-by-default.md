# Kyverno's PolicyException objects can be created in any namespace by default

**Severity**: High


**CVSS Score**: 2.7 (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N)


**Source**: trivy



**Identifiers**: CVE-2024-48921, CWE-863, CWE-285


## Description
Kyverno is a policy engine designed for Kubernetes. A kyverno ClusterPolicy, ie. "disallow-privileged-containers," can be overridden by the creation of a PolicyException in a random namespace. By design, PolicyExceptions are consumed from any namespace. Administrators may not recognize that this allows users with privileges to non-kyverno namespaces to create exceptions. This vulnerability is fixed in 1.13.0.


## Remediation
Update github.com/kyverno/kyverno from 1.9.2 to 1.13.0.



## References

- <https://avd.aquasec.com/nvd/cve-2024-48921>

- <https://github.com/kyverno/kyverno>

- <https://github.com/kyverno/kyverno/security/advisories/GHSA-qjvc-p88j-j9rm>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-48921>





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
