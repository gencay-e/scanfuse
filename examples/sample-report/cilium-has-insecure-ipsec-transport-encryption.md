# Cilium has insecure IPsec transport encryption

**Severity**: High


**CVSS Score**: 8.0 (CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)


**Source**: trivy




**Identifiers**: CVE-2024-28860, CWE-326


## Description
Cilium is a networking, observability, and security solution with an eBPF-based dataplane. Users of IPsec transparent encryption in Cilium may be vulnerable to cryptographic attacks that render the transparent encryption ineffective. In particular, Cilium is vulnerable to chosen plaintext, key recovery, replay attacks by a man-in-the-middle attacker. These attacks are possible due to an ESP sequence number collision when multiple nodes are configured with the same key. Fixed versions of Cilium use unique keys for each IPsec tunnel established between nodes, resolving all of the above attacks. This vulnerability is fixed in 1.13.13, 1.14.9, and 1.15.3.


## Remediation
Update github.com/cilium/cilium from 1.14.5 to 1.13.14, 1.14.9, 1.15.3.



## References

- <https://avd.aquasec.com/nvd/cve-2024-28860>

- <https://docs.cilium.io/en/stable/security/network/encryption-ipsec>

- <https://github.com/cilium/cilium>

- <https://github.com/cilium/cilium/commit/311fbce5280491cddceab178d83b06fa23688c72>

- <https://github.com/cilium/cilium/commit/a1742b478306fa256cd27df1039dfae0537b4149>

- <https://github.com/cilium/cilium/commit/a652c123331852cca90c74202f993d4170fd37fa>

- <https://github.com/cilium/cilium/security/advisories/GHSA-pwqm-x5x6-5586>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-28860>

- <https://pkg.go.dev/vuln/GO-2024-2666>





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
