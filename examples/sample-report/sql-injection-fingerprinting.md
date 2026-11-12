# SQL Injection Fingerprinting

**Severity**: High


**Source**: zap


**Port**: 80/tcp



**Location**: /demo/SQLI2.php \[username parameter\]



**Identifiers**: zap-plugin:40004


## Description
SQL injection may be possible.


## Remediation
Do not trust client side input even if there is client side validation.  In general, If the input string is numeric, type check it.
If the application used JDBC, use PreparedStatement or CallableStatement with parameters passed by '?'
If the application used ASP, use ADO Command Objects with strong type checking and parameterized query.
If stored procedure or bind variables can be used, use it for parameter passing into query.  Do not just concatenate string into query in the stored procedure!
Do not create dynamic SQL query by simple string concatentation.
Use minimum database user privilege for the application.  This does not eliminate SQL injection but minimize its damage.  Eg if the application require reading one table only, grant such access to the application.  Avoid using 'sa' or 'db-owner'.



## References

- <http://www.owasp.org/documentation/guide>

- <http://www.sqlsecurity.com/DesktopDefault.aspx?tabid=23>

- <http://www.spidynamics.com/whitepapers/WhitepaperSQLInjection.pdf>

- <http://www.integrigy.com/info/IntegrigyIntrotoSQLInjectionAttacks.pdf>





## Hosts

- 10.2.100.1


## Evidence

### http-request


```
Request: http://10.2.100.1/demo/SQLI2.php
Parameter: username
Attack: 1'INJECTED_PARAM
```

### other-info


```
SQL
```
