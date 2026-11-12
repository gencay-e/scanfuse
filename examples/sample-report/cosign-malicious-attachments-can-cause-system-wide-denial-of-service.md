# cosign: Malicious attachments can cause system-wide denial of service

**Severity**: Medium


**CVSS Score**: 4.2 (CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H)


**Source**: trivy




**Identifiers**: CVE-2024-29902, CWE-770


## Description
Cosign provides code signing and transparency for containers and binaries. Prior to version 2.2.4, a remote image with a malicious attachment can cause denial of service of the host machine running Cosign. This can impact other services on the machine that rely on having memory available such as a Redis database which can result in data loss. It can also impact the availability of other services on the machine that will not be available for the duration of the machine denial. The root cause of this issue is that Cosign reads the attachment from a remote image entirely into memory without checking the size of the attachment first. As such, a large attachment can make Cosign read a large attachment into memory; If the attachments size is larger than the machine has memory available, the machine will be denied of service. The Go runtime will make a SigKill after a few seconds of system-wide denial. This issue can allow a supply-chain escalation from a compromised registry to the Cosign user: If an attacher has compromised a registry or the account of an image vendor, they can include a malicious attachment and hurt the image consumer. Version 2.2.4 contains a patch for the vulnerability.


## Remediation
Update github.com/sigstore/cosign/v2 from 2.2.2 to 2.2.4.



## References

- <https://avd.aquasec.com/nvd/cve-2024-29902>

- <https://access.redhat.com/security/cve/CVE-2024-29902>

- <https://github.com/google/go-containerregistry/blob/a0658aa1d0cc7a7f1bcc4a3af9155335b6943f40/pkg/v1/remote/layer.go#L36-L40>

- <https://github.com/sigstore/cosign>

- <https://github.com/sigstore/cosign/blob/9bc3ee309bf35d2f6e17f5d23f231a3d8bf580bc/pkg/oci/remote/remote.go#L228-L239>

- <https://github.com/sigstore/cosign/commit/629f5f8fa672973503edde75f84dcd984637629e>

- <https://github.com/sigstore/cosign/releases/tag/v2.2.4>

- <https://github.com/sigstore/cosign/security/advisories/GHSA-88jx-383q-w4qc>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-29902>

- <https://www.cve.org/CVERecord?id=CVE-2024-29902>





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
