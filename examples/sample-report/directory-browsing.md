# Directory browsing

**Severity**: Medium


**Source**: zap


**Port**: 80/tcp



**Location**: /demo/DirectoryIndexing/



**Identifiers**: zap-plugin:0


## Description
It is possible to view the directory listing.  Directory listing may reveal hidden scripts, include files , backup source files etc which be accessed to read sensitive information.


## Remediation
Disable directory browsing.  If this is required, make sure the listed files does not induce risks.



## References

- <http://httpd.apache.org/docs/mod/core.html#options>

- <http://alamo.satlug.org/pipermail/satlug/2002-February/000053.html>





## Hosts

- 10.2.100.1


## Evidence

### http-request


```
Request: http://10.2.100.1/demo/DirectoryIndexing/
```
