# Pentest Report Summary

## Import status

Complete. All inputs were read.


## Executive Summary
Total Findings: 39

### Risk Matrix
| Severity | Count |
|----------|-------|
| Critical | 1 |
| High     | 13 |
| Medium   | 25 |
| Low      | 0 |
| Info     | 0 |

## Findings Overview

- [Critical] [moby: Authz zero length regression](moby-authz-zero-length-regression.md) (Source: trivy, 1 host)

- [High] [\[SSL Scanner\] Offer SSLv3](ssl-scanner-offer-sslv3.md) (Source: burp, 1 host)

- [High] [\[SSL Scanner\] POODLE (SSLv3)](ssl-scanner-poodle-sslv3.md) (Source: burp, 1 host)

- [High] [Asymmetric Private Key](asymmetric-private-key.md) (Source: trivy, 1 host)

- [High] [Attacker can cause Kyverno user to unintentionally consume insecure image](attacker-can-cause-kyverno-user-to-unintentionally-consume-insecure-image.md) (Source: trivy, 1 host)

- [High] [Cilium has insecure IPsec transport encryption](cilium-has-insecure-ipsec-transport-encryption.md) (Source: trivy, 1 host)

- [High] [Cilium leaks sensitive information in cilium-bugtool](cilium-leaks-sensitive-information-in-cilium-bugtool.md) (Source: trivy, 1 host)

- [High] [Cross Site Scripting](cross-site-scripting.md) (Source: zap, 1 host)

- [High] [External service interaction (DNS)](external-service-interaction-dns.md) (Source: burp, 1 host)

- [High] [Intermittent HTTP policy bypass](intermittent-http-policy-bypass.md) (Source: trivy, 1 host)

- [High] [Kyverno's PolicyException objects can be created in any namespace by default](kyverno-s-policyexception-objects-can-be-created-in-any-namespace-by-default.md) (Source: trivy, 1 host)

- [High] [Path Traversal](path-traversal.md) (Source: zap, 1 host)

- [High] [SQL Injection](sql-injection.md) (Source: zap, 1 host)

- [High] [SQL Injection Fingerprinting](sql-injection-fingerprinting.md) (Source: zap, 1 host)

- [Medium] [\[SSL Scanner\] BREACH](ssl-scanner-breach.md) (Source: burp, 1 host)

- [Medium] [Cilium's CIDR deny policies may not take effect when a more narrow CIDR allow is present](cilium-s-cidr-deny-policies-may-not-take-effect-when-a-more-narrow-cidr-allow-is-present.md) (Source: trivy, 1 host)

- [Medium] [cosign: Malicious artifects can cause machine-wide denial of service](cosign-malicious-artifects-can-cause-machine-wide-denial-of-service.md) (Source: trivy, 1 host)

- [Medium] [cosign: Malicious attachments can cause system-wide denial of service](cosign-malicious-attachments-can-cause-system-wide-denial-of-service.md) (Source: trivy, 1 host)

- [Medium] [Cross Site Request Forgery](cross-site-request-forgery.md) (Source: zap, 1 host)

- [Medium] [Directory browsing](directory-browsing.md) (Source: zap, 1 host)

- [Medium] [go-retryablehttp: url might write sensitive information to log file](go-retryablehttp-url-might-write-sensitive-information-to-log-file.md) (Source: trivy, 1 host)

- [Medium] [golang: net/http, x/net/http2: unlimited number of CONTINUATION frames causes DoS](golang-net-http-x-net-http2-unlimited-number-of-continuation-frames-causes-dos.md) (Source: trivy, 1 host)

- [Medium] [jose-go: improper handling of highly compressed data](jose-go-improper-handling-of-highly-compressed-data.md) (Source: trivy, 1 host)

- [Medium] [JWT token](jwt-token.md) (Source: trivy, 1 host)

- [Medium] [Kyverno resource with a deletionTimestamp may allow policy circumvention](kyverno-resource-with-a-deletiontimestamp-may-allow-policy-circumvention.md) (Source: trivy, 1 host)

- [Medium] [kyverno seccomp control can be circumvented](kyverno-seccomp-control-can-be-circumvented.md) (Source: trivy, 1 host)

- [Medium] [Kyverno vulnerable due to usage of insecure cipher](kyverno-vulnerable-due-to-usage-of-insecure-cipher.md) (Source: trivy, 1 host)

- [Medium] [mholt/archiver: path traversal vulnerability](mholt-archiver-path-traversal-vulnerability.md) (Source: trivy, 1 host)

- [Medium] [Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness](microsoft-windows-remote-desktop-protocol-server-man-in-the-middle-weakness.md) (Source: nessus, 2 hosts)

- [Medium] [opa: OPA SMB Force-Authentication](opa-opa-smb-force-authentication.md) (Source: trivy, 1 host)

- [Medium] [Policy bypass for Host Firewall policy due to race condition in Cilium agent](policy-bypass-for-host-firewall-policy-due-to-race-condition-in-cilium-agent.md) (Source: trivy, 1 host)

- [Medium] [SMB Signing Disabled](smb-signing-disabled.md) (Source: nessus, 2 hosts)

- [Medium] [SSL certificate](ssl-certificate.md) (Source: burp, 1 host)

- [Medium] [Strict Transport Security Misconfiguration](strict-transport-security-misconfiguration.md) (Source: burp, 1 host)

- [Medium] [Terminal Services Encryption Level is Medium or Low](terminal-services-encryption-level-is-medium-or-low.md) (Source: nessus, 2 hosts)

- [Medium] [Unencrypted ingress/health traffic when using Wireguard transparent encryption](unencrypted-ingress-health-traffic-when-using-wireguard-transparent-encryption.md) (Source: trivy, 1 host)

- [Medium] [Unencrypted traffic between nodes when using IPsec and L7 policies](unencrypted-traffic-between-nodes-when-using-ipsec-and-l7-policies.md) (Source: trivy, 1 host)

- [Medium] [Unencrypted traffic between nodes when using WireGuard and L7 policies](unencrypted-traffic-between-nodes-when-using-wireguard-and-l7-policies.md) (Source: trivy, 1 host)

- [Medium] [Unencrypted traffic between pods when using Wireguard and an external kvstore](unencrypted-traffic-between-pods-when-using-wireguard-and-an-external-kvstore.md) (Source: trivy, 1 host)


## Affected Hosts


  
    
      
    
    
      
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
      
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
      
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
  

  
    
      
    
    
      
    
  
    
      
    
    
      
    
  

  
    
      
    
    
  
    
      
    
    
  

  
    
      
    
    
  
    
      
    
    
  



- 10.2.100.1

- .

- 127.0.0.1 (https://127.0.0.1)

- 10.31.112.24 (qa3app04)

- 10.31.112.23 (qa3app03)
