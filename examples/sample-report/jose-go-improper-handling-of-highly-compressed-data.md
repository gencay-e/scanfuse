# jose-go: improper handling of highly compressed data

**Severity**: Medium


**CVSS Score**: 4.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L)


**Source**: trivy




**Identifiers**: CVE-2024-28180, CWE-409


## Description
Package jose aims to provide an implementation of the Javascript Object Signing and Encryption set of standards. An attacker could send a JWE containing compressed data that used large amounts of memory and CPU when decompressed by Decrypt or DecryptMulti. Those functions now return an error if the decompressed data would exceed 250kB or 10x the compressed size (whichever is larger). This vulnerability has been patched in versions 4.0.1, 3.0.3 and 2.6.3.


## Remediation
Update github.com/go-jose/go-jose/v3 from 3.0.1 to 3.0.3.



## References

- <https://avd.aquasec.com/nvd/cve-2024-28180>

- <https://access.redhat.com/errata/RHSA-2024:3827>

- <https://access.redhat.com/security/cve/CVE-2024-28180>

- <https://bugzilla.redhat.com/2268017>

- <https://bugzilla.redhat.com/2268820>

- <https://bugzilla.redhat.com/2268854>

- <https://bugzilla.redhat.com/show_bug.cgi?id=2268017>

- <https://bugzilla.redhat.com/show_bug.cgi?id=2268820>

- <https://bugzilla.redhat.com/show_bug.cgi?id=2268854>

- <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45290>

- <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-28176>

- <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-28180>

- <https://errata.almalinux.org/9/ALSA-2024-3827.html>

- <https://errata.rockylinux.org/RLSA-2024:3827>

- <https://github.com/go-jose/go-jose>

- <https://github.com/go-jose/go-jose/commit/0dd4dd541c665fb292d664f77604ba694726f298>

- <https://github.com/go-jose/go-jose/commit/add6a284ea0f844fd6628cba637be5451fe4b28a>

- <https://github.com/go-jose/go-jose/commit/f4c051a0653d78199a053892f7619ebf96339502>

- <https://github.com/go-jose/go-jose/security/advisories/GHSA-c5q2-7r4c-mv6g>

- <https://linux.oracle.com/cve/CVE-2024-28180.html>

- <https://linux.oracle.com/errata/ELSA-2024-3968.html>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GD2GSBQTBLYADASUBHHZV2CZPTSLIPQJ>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GD2GSBQTBLYADASUBHHZV2CZPTSLIPQJ/>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/I6MMWFBOXJA6ZCXNVPDFJ4XMK5PVG5RG>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/I6MMWFBOXJA6ZCXNVPDFJ4XMK5PVG5RG/>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IJ6LAJJ2FTA2JVVOACCV5RZTOIZLXUNJ>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IJ6LAJJ2FTA2JVVOACCV5RZTOIZLXUNJ/>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JNPMXL36YGS3GQEVI3Q5HKHJ7YAAQXL5>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JNPMXL36YGS3GQEVI3Q5HKHJ7YAAQXL5/>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KXKGNCRU7OTM5AHC7YIYBNOWI742PRMY>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KXKGNCRU7OTM5AHC7YIYBNOWI742PRMY/>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MSOMHDKRPU3A2JEMRODT2IREDFBLVPGS>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MSOMHDKRPU3A2JEMRODT2IREDFBLVPGS/>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UG5FSEYJ3GP27FZXC5YAAMMEC5XWKJHG>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UG5FSEYJ3GP27FZXC5YAAMMEC5XWKJHG/>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UJO2U5ACZVACNQXJ5EBRFLFW6DP5BROY>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UJO2U5ACZVACNQXJ5EBRFLFW6DP5BROY/>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XJDO5VSIAOGT2WP63AXAAWNRSVJCNCRH>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XJDO5VSIAOGT2WP63AXAAWNRSVJCNCRH/>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-28180>

- <https://www.cve.org/CVERecord?id=CVE-2024-28180>




## Reported by


### trivy

**Severity**: Medium, **CVSS Score**: 4.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L)

Package jose aims to provide an implementation of the Javascript Object Signing and Encryption set of standards. An attacker could send a JWE containing compressed data that used large amounts of memory and CPU when decompressed by Decrypt or DecryptMulti. Those functions now return an error if the decompressed data would exceed 250kB or 10x the compressed size (whichever is larger). This vulnerability has been patched in versions 4.0.1, 3.0.3 and 2.6.3.


**Remediation**: Update github.com/go-jose/go-jose/v3 from 3.0.1 to 3.0.3.



### trivy

**Severity**: Medium, **CVSS Score**: 4.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L)

Package jose aims to provide an implementation of the Javascript Object Signing and Encryption set of standards. An attacker could send a JWE containing compressed data that used large amounts of memory and CPU when decompressed by Decrypt or DecryptMulti. Those functions now return an error if the decompressed data would exceed 250kB or 10x the compressed size (whichever is larger). This vulnerability has been patched in versions 4.0.1, 3.0.3 and 2.6.3.


**Remediation**: Update gopkg.in/go-jose/go-jose.v2 from 2.6.1 to 2.6.3.




## Hosts

- unknown (.)


## Evidence

### target (trivy)


```
go.mod
```

### package (trivy)


```
Package: github.com/go-jose/go-jose/v3
Installed: 3.0.1
```

### package (trivy)


```
Package: gopkg.in/go-jose/go-jose.v2
Installed: 2.6.1
```
