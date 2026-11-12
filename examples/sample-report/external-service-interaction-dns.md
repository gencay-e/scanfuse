# External service interaction (DNS)

**Severity**: High


**Source**: burp


**Port**: 443/tcp



**Affected**:

- 127.0.0.1 /




**Identifiers**: burp-type:3146240, CWE-918, CWE-406


## Description
It is possible to induce the application to perform server-side DNS lookups of arbitrary domain names.

The payload xxxxxxxxxxxxxxxxxxxxxx.burpcollaborator.net was submitted in the SSL SNI value and the HTTP Host header.

The application performed a DNS lookup of the specified domain.

External service interaction arises when it is possible to induce an application to interact with an arbitrary external service, such as a web or mail server. The ability to trigger arbitrary external service interactions does not constitute a vulnerability in its own right, and in some cases might even be the intended behavior of the application.
However, in many cases, it can indicate a vulnerability with serious consequences.

In cases where DNS-based interactions can be triggered, it is normally possible to trigger interactions using other service types, and these are reported as separate issues.
If a payload that specifies a particular service type (e.g. a URL) triggers only a DNS-based interaction,
then this strongly indicates that the application attempted to connect using that other service,
but was prevented from doing so by egress filters in place at the network layer. The ability to send requests to other systems can allow the vulnerable server to be used as an attack proxy.
By submitting suitable payloads, an attacker can cause the application server to attack other systems that it can interact with.
This may include public third-party systems, internal systems within the same organization, or services available on the local loopback adapter of the application server itself.
Depending on the network architecture, this may expose highly vulnerable internal services that are not otherwise accessible to external attackers.


## Remediation
You should review the purpose and intended use of the relevant application functionality,
and determine whether the ability to trigger arbitrary external service interactions is intended behavior.
If so, you should be aware of the types of attacks that can be performed via this behavior and take appropriate measures.
These measures might include blocking network access from the application server to other internal systems, and hardening the application server itself to remove any services available on the local loopback adapter.

If the ability to trigger arbitrary external service interactions is not intended behavior, then you should implement a whitelist of permitted services and hosts, and block any interactions that do not appear on this whitelist.



## References

- <http://blog.portswigger.net/2015/04/introducing-burp-collaborator.html>

- <https://cwe.mitre.org/data/definitions/918.html>

- <https://cwe.mitre.org/data/definitions/406.html>





## Hosts

- 127.0.0.1 (https://127.0.0.1)


## Evidence

### path


```
/
```

### burp-details


```
Confidence: Certain
```
