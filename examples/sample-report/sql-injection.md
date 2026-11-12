# SQL Injection

**Severity**: High


**Source**: zap


**Port**: 80/tcp



**Affected**:

- 10.2.100.1 /demo/SQLI2.php \[username parameter\]




**Identifiers**: zap-plugin:40005


## Description
SQL injection is possible.  User parameters submitted will be formulated into a SQL query for database processing.  If the query is built by simple 'string concatenation', it is possible to modify the meaning of the query by carefully crafting the parameters.  Depending on the access right and type of database used, tampered query can be used to retrieve sensitive information from the database or execute arbitrary code.  MS SQL and PostGreSQL, which supports multiple statements, may be exploited if the database access right is more powerful.
This can occur in URL query strings, POST paramters or even cookies.  Currently check on cookie is not supported by Paros.  You should check SQL injection manually as well as some blind SQL injection areas cannot be discovered by this check.


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
Attack: 1%27INJECTED_PARAM'INJECTED_PARAM
```

### other-info


```
SQL
```
