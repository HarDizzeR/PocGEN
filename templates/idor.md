# {title}
**Vulnerability Type:** Insecure Direct Object Reference (IDOR)  
**Severity:** {severity}  
**Date:** {date}

## Summary
An Insecure Direct Object Reference (IDOR) vulnerability was discovered that allows unauthorized access to resources by manipulating object identifiers.

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
2. Identify the object identifier in the `{param}` parameter
3. Replace the parameter value with: `{payload}`
4. Observe unauthorized access to another user's resource

### Example Request
```http
GET {url}?{param}={payload} HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (compatible; Security-Test/1.0)
Cookie: session=your_session_cookie
```

### Expected Behavior
The application should allow access to resource with ID `{payload}` without proper authorization checks.

## Impact
- Unauthorized access to sensitive user data
- Privacy violations
- Data modification or deletion
- Privilege escalation
- Compliance violations (GDPR, HIPAA, etc.)

## Attack Scenarios
1. **Horizontal Privilege Escalation:** Access other users' data at the same privilege level
2. **Vertical Privilege Escalation:** Access admin or higher-privileged resources
3. **Data Enumeration:** Systematic access to multiple resources

## Risk Rating
**{severity}** - IDOR vulnerabilities can lead to unauthorized data access and privacy breaches.

## Remediation
1. Implement proper access control checks for all resources
2. Use indirect object references (mapping tables)
3. Validate user permissions for each resource access
4. Implement resource-level authorization
5. Use UUIDs instead of sequential IDs
6. Log and monitor access attempts

## References
- [OWASP Top 10 A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
