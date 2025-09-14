# {title}
**Vulnerability Type:** Missing Rate Limiting  
**Severity:** {severity}  
**Date:** {date}

## Summary
A missing rate limiting vulnerability was discovered that allows attackers to perform automated attacks without restrictions.

## Vulnerable Endpoint
- **URL:** `{url}`
- **Parameter:** `{param}` (if applicable)
- **Method:** GET/POST

## Proof of Concept

### Test Payload/Username
```
{payload}
```

### Steps to Reproduce
1. Navigate to: `{url}`
2. Send multiple rapid requests to the endpoint
3. Use automated tools to send 100+ requests per minute
4. Observe that no rate limiting is enforced

### Example Attack Script
```bash
#!/bin/bash
# Brute force attack script
for i in {{1..1000}}; do
    curl -X POST "{url}" \
         -d "{param}={payload}&password=password$i" \
         -H "Content-Type: application/x-www-form-urlencoded"
    echo "Attempt $i completed"
done
```

### Example Request
```http
POST {url} HTTP/1.1
Host: {host}
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (compatible; Security-Test/1.0)

{param}={payload}&password=testpassword
```

## Impact
- Brute force attacks on authentication
- Account enumeration
- Password spraying attacks
- Resource exhaustion/DoS
- Automated abuse of functionality
- API abuse and resource consumption

## Attack Scenarios
1. **Credential Brute Force:** Unlimited login attempts
2. **Account Enumeration:** Testing multiple usernames
3. **Password Spraying:** Testing common passwords across accounts
4. **API Abuse:** Unlimited API calls causing service degradation
5. **Form Spam:** Automated submission of forms

## Risk Rating
**{severity}** - Missing rate limiting enables various automated attacks and resource abuse.

## Remediation
1. Implement rate limiting per IP address
2. Use account-based rate limiting for authentication
3. Implement CAPTCHA after failed attempts
4. Add progressive delays for repeated failures
5. Monitor and alert on unusual request patterns
6. Use Web Application Firewall (WAF) with rate limiting
7. Implement proper session management

### Recommended Rate Limits
- **Login Attempts:** 5 attempts per 15 minutes per IP
- **Password Reset:** 3 requests per hour per email
- **API Endpoints:** 100 requests per minute per API key
- **Form Submissions:** 10 submissions per minute per IP

## References
- [OWASP Authentication Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/Authentication_Cheat_Sheet.html)
- [CWE-799: Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
