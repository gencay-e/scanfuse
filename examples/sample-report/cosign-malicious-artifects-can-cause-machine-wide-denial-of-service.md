# cosign: Malicious artifects can cause machine-wide denial of service

**Severity**: Medium


**CVSS Score**: 4.2 (CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H)


**Source**: trivy



**Identifiers**: CVE-2024-29903, CWE-770


## Description
Cosign provides code signing and transparency for containers and binaries. Prior to version 2.2.4, maliciously-crafted software artifacts can cause denial of service of the machine running Cosign thereby impacting all services on the machine. The root cause is that Cosign creates slices based on the number of signatures, manifests or attestations in untrusted artifacts. As such, the untrusted artifact can control the amount of memory that Cosign allocates. The exact issue is Cosign allocates excessive memory on the lines that creates a slice of the same length as the manifests. Version 2.2.4 contains a patch for the vulnerability.


## Remediation
Update github.com/sigstore/cosign/v2 from 2.2.2 to 2.2.4.



## References

- <https://avd.aquasec.com/nvd/cve-2024-29903>

- <https://access.redhat.com/security/cve/CVE-2024-29903>

- <https://github.com/sigstore/cosign>

- <https://github.com/sigstore/cosign/blob/14795db16417579fac0c00c11e166868d7976b61/pkg/cosign/verify.go#L948-L955>

- <https://github.com/sigstore/cosign/blob/286a98a4a99c1b2f32f84b0d560e324100312280/pkg/oci/remote/signatures.go#L56-L70>

- <https://github.com/sigstore/cosign/commit/629f5f8fa672973503edde75f84dcd984637629e>

- <https://github.com/sigstore/cosign/releases/tag/v2.2.4>

- <https://github.com/sigstore/cosign/security/advisories/GHSA-95pr-fxf5-86gv>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-29903>

- <https://www.cve.org/CVERecord?id=CVE-2024-29903>





## Hosts

- unknown (.)


## Evidence

### target


```
go.mod
```

### package


```
Package: github.com/sigstore/cosign/v2
Installed: 2.2.2
```
