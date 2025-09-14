# {title}

**Vulnerability Type:** Missing/Weak Security Headers  
**Severity:** {severity}  
**Date:** {date}

## Summary
The application is missing or has misconfigured security headers that help protect against various attacks.

## Vulnerable Endpoint
- **URL:** `{url}`

## Missing/Weak Security Headers
{missing_headers}

## Proof of Concept

### Steps to Reproduce
1. Send a request to: `{url}`
2. Examine the response headers
3. Verify the absence or misconfiguration of security headers

### Example Request
```http
GET / HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (compatible; Security-Test/1.0)
```

### Current Response (Missing Headers)
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1234
Set-Cookie: sessionid=abc123
<!-- Missing security headers -->
```

## Impact
- **Missing HSTS:** Man-in-the-middle attacks via HTTP downgrade
- **Missing CSP:** Cross-site scripting (XSS) attacks
- **Missing X-Frame-Options:** Clickjacking attacks
- **Missing Referrer-Policy:** Information leakage via referrer headers
- **Missing X-Content-Type-Options:** MIME-type confusion attacks

## Risk Rating
**{severity}** - Missing security headers increase the attack surface and vulnerability to various client-side attacks.

## Remediation

### Recommended Security Headers
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-XSS-Protection: 1; mode=block
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

### Implementation Steps
1. Configure web server or application to send security headers
2. Implement Content Security Policy (CSP)
3. Enable HTTP Strict Transport Security (HSTS)
4. Set appropriate frame options
5. Configure referrer policy
6. Regular testing and monitoring

## References
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN HTTP Headers Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [Security Headers Checker](https://securityheaders.com/)