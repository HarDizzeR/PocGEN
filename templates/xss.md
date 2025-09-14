# {title}

**Vulnerability Type:** Cross-Site Scripting (XSS)  
**Severity:** {severity}  
**Date:** {date}

## Summary
A Cross-Site Scripting (XSS) vulnerability was discovered in the application that allows injection of malicious scripts.

## Vulnerable Endpoint
- **URL:** `{url}`
- **Parameter:** `{param}`
- **Method:** GET/POST

## Proof of Concept

### Payload
```
{payload}
```

### Steps to Reproduce
1. Navigate to: `{url}`
2. Inject the following payload in the `{param}` parameter:
   ```
   {payload}
   ```
3. Observe the script execution in the browser

### Example Request
```http
GET {url}?{param}={payload_encoded} HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (compatible; Security-Test/1.0)
```

## Impact
- Arbitrary JavaScript execution in victim's browser
- Session hijacking potential
- Defacement of web pages
- Credential theft
- Malware distribution

## Risk Rating
**{severity}** - XSS vulnerabilities can lead to complete compromise of user sessions and sensitive data theft.

## Remediation
1. Implement proper input validation and sanitization
2. Use Content Security Policy (CSP) headers
3. Encode output data before rendering
4. Use HTTPOnly and Secure flags for cookies
5. Implement proper XSS filters

## References
- [OWASP XSS Prevention Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)