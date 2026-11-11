# JWT token

**Severity**: Medium


**Source**: trivy



**Identifiers**: trivy-rule:jwt-token


## Description
Secret detected: jwt-token





## Reported by


### trivy

**Severity**: Medium

Secret detected: jwt-token




## Hosts

- unknown (.)


## Evidence

### target (trivy)


```
frontend/src/app/app.guard.spec.ts
```

### match (trivy)


```
Match: ocalStorage.setItem('token', '***********************************************************************************************************************************************************')
```

### target (trivy)


```
frontend/src/app/last-login-ip/last-login-ip.component.spec.ts
```

### match (trivy)


```
Match: ocalStorage.setItem('token', '*******************************************************************************************************************************')
```
