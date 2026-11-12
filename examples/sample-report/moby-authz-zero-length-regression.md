# moby: Authz zero length regression

**Severity**: Critical


**CVSS Score**: 9.9 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)


**Source**: trivy




**Identifiers**: CVE-2024-41110, CWE-187, CWE-444, CWE-863


## Description
Moby is an open-source project created by Docker for software containerization. A security vulnerability has been detected in certain versions of Docker Engine, which could allow an attacker to bypass authorization plugins (AuthZ) under specific circumstances. The base likelihood of this being exploited is low.

Using a specially-crafted API request, an Engine API client could make the daemon forward the request or response to an authorization plugin without the body. In certain circumstances, the authorization plugin may allow a request which it would have otherwise denied if the body had been forwarded to it.

A security issue was discovered In 2018, where an attacker could bypass AuthZ plugins using a specially crafted API request. This could lead to unauthorized actions, including privilege escalation. Although this issue was fixed in Docker Engine v18.09.1 in January 2019, the fix was not carried forward to later major versions, resulting in a regression. Anyone who depends on authorization plugins that introspect the request and/or response body to make access control decisions is potentially impacted.

Docker EE v19.03.x and all versions of Mirantis Container Runtime are not vulnerable.

docker-ce v27.1.1 containes patches to fix the vulnerability. Patches have also been merged into the master, 19.03, 20.0, 23.0, 24.0, 25.0, 26.0, and 26.1 release branches. If one is unable to upgrade immediately, avoid using AuthZ plugins and/or restrict access to the Docker API to trusted parties, following the principle of least privilege.


## Remediation
Update github.com/docker/docker from 25.0.5+incompatible to 23.0.15, 26.1.5, 27.1.1, 25.0.6.



## References

- <https://avd.aquasec.com/nvd/cve-2024-41110>

- <https://access.redhat.com/security/cve/CVE-2024-41110>

- <https://github.com/moby/moby>

- <https://github.com/moby/moby/commit/411e817ddf710ff8e08fa193da80cb78af708191>

- <https://github.com/moby/moby/commit/42f40b1d6dd7562342f832b9cd2adf9e668eeb76>

- <https://github.com/moby/moby/commit/65cc597cea28cdc25bea3b8a86384b4251872919>

- <https://github.com/moby/moby/commit/852759a7df454cbf88db4e954c919becd48faa9b>

- <https://github.com/moby/moby/commit/a31260625655cff9ae226b51757915e275e304b0>

- <https://github.com/moby/moby/commit/a79fabbfe84117696a19671f4aa88b82d0f64fc1>

- <https://github.com/moby/moby/commit/ae160b4edddb72ef4bd71f66b975a1a1cc434f00>

- <https://github.com/moby/moby/commit/ae2b3666c517c96cbc2adf1af5591a6b00d4ec0f>

- <https://github.com/moby/moby/commit/cc13f952511154a2866bddbb7dddebfe9e83b801>

- <https://github.com/moby/moby/commit/fc274cd2ff4cf3b48c91697fb327dd1fb95588fb>

- <https://github.com/moby/moby/security/advisories/GHSA-v23v-6jw2-98fq>

- <https://nvd.nist.gov/vuln/detail/CVE-2024-41110>

- <https://www.cve.org/CVERecord?id=CVE-2024-41110>

- <https://www.docker.com/blog/docker-security-advisory-docker-engine-authz-plugin>





## Hosts

- unknown (.)


## Evidence

### target


```
go.mod
```

### package


```
Package: github.com/docker/docker
Installed: 25.0.5+incompatible
```
