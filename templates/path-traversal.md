# {title}
**Vulnerability Type:** Path Traversal (Directory Traversal)  
**Severity:** {severity}  
**Date:** {date}

## Summary
A Path Traversal vulnerability was discovered that allows attackers to access files and directories outside the intended directory structure.

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
2. Inject the path traversal payload in the `{param}` parameter:
   ```
   {payload}
   ```
3. Observe access to system files outside the web root

### Example Request
```http
GET {url}?{param}={payload_encoded} HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (compatible; Security-Test/1.0)
```

### Expected Response
The server should return the contents of system files like `/etc/passwd` or other sensitive files.

## Impact
- Unauthorized access to system files
- Configuration file disclosure
- Source code exposure
- Credential theft from configuration files
- System information disclosure
- Potential remote code execution

## Common Target Files
- `/etc/passwd` - Unix/Linux user information
- `/etc/shadow` - Unix/Linux password hashes
- `C:\Windows\System32\drivers\etc\hosts` - Windows hosts file
- `web.config` - ASP.NET configuration
- `.env` - Environment variables
- `config.php` - PHP configuration files

## Risk Rating
**{severity}** - Path traversal can lead to sensitive file disclosure and system compromise.

## Remediation
1. Implement proper input validation and sanitization
2. Use whitelisted allowed file paths
3. Avoid user input in file path construction
4. Implement proper access controls at the OS level
5. Use chroot jails or similar containment mechanisms
6. Regular security audits and penetration testing

## References
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
