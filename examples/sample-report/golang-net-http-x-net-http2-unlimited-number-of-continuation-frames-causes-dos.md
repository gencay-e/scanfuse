# golang: net/http, x/net/http2: unlimited number of CONTINUATION frames causes DoS

**Severity**: Medium


**CVSS Score**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)


**Source**: trivy




**Identifiers**: CVE-2023-45288


## Description
An attacker may cause an HTTP/2 endpoint to read arbitrary amounts of header data by sending an excessive number of CONTINUATION frames. Maintaining HPACK state requires parsing and processing all HEADERS and CONTINUATION frames on a connection. When a request's headers exceed MaxHeaderBytes, no memory is allocated to store the excess headers, but they are still parsed. This permits an attacker to cause an HTTP/2 endpoint to read arbitrary amounts of header data, all associated with a request which is going to be rejected. These headers can include Huffman-encoded data which is significantly more expensive for the receiver to decode than for an attacker to send. The fix sets a limit on the amount of excess header frames we will process before closing a connection.


## Remediation
Update golang.org/x/net from 0.22.0 to 0.23.0.



## References

- <https://avd.aquasec.com/nvd/cve-2023-45288>

- <http://www.openwall.com/lists/oss-security/2024/04/03/16>

- <http://www.openwall.com/lists/oss-security/2024/04/05/4>

- <https://access.redhat.com/errata/RHSA-2024:2724>

- <https://access.redhat.com/security/cve/CVE-2023-45288>

- <https://bugzilla.redhat.com/2268017>

- <https://bugzilla.redhat.com/2268018>

- <https://bugzilla.redhat.com/2268019>

- <https://bugzilla.redhat.com/2268273>

- <https://bugzilla.redhat.com/show_bug.cgi?id=2268017>

- <https://bugzilla.redhat.com/show_bug.cgi?id=2268018>

- <https://bugzilla.redhat.com/show_bug.cgi?id=2268019>

- <https://bugzilla.redhat.com/show_bug.cgi?id=2268273>

- <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45288>

- <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45289>

- <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45290>

- <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24783>

- <https://errata.almalinux.org/9/ALSA-2024-2724.html>

- <https://errata.rockylinux.org/RLSA-2024:2724>

- <https://go.dev/cl/576155>

- <https://go.dev/issue/65051>

- <https://groups.google.com/g/golang-announce/c/YgW0sx8mN3M>

- <https://kb.cert.org/vuls/id/421644>

- <https://linux.oracle.com/cve/CVE-2023-45288.html>

- <https://linux.oracle.com/errata/ELSA-2024-3346.html>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QRYFHIQ6XRKRYBI2F5UESH67BJBQXUPT>

- <https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QRYFHIQ6XRKRYBI2F5UESH67BJBQXUPT/>

- <https://nowotarski.info/http2-continuation-flood-technical-details>

- <https://nowotarski.info/http2-continuation-flood/>

- <https://nvd.nist.gov/vuln/detail/CVE-2023-45288>

- <https://pkg.go.dev/vuln/GO-2024-2687>

- <https://security.netapp.com/advisory/ntap-20240419-0009>

- <https://security.netapp.com/advisory/ntap-20240419-0009/>

- <https://ubuntu.com/security/notices/USN-6886-1>

- <https://ubuntu.com/security/notices/USN-7109-1>

- <https://ubuntu.com/security/notices/USN-7111-1>

- <https://www.cve.org/CVERecord?id=CVE-2023-45288>

- <https://www.kb.cert.org/vuls/id/421644>





## Hosts

- unknown (.)


## Evidence

### target


```
go.mod
```

### package


```
Package: golang.org/x/net
Installed: 0.22.0
```
