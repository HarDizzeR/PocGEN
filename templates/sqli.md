# {title}

**Vulnerability Type:** SQL Injection  
**Severity:** {severity}  
**Date:** {date}

## Summary
A SQL Injection vulnerability was identified that allows manipulation of database queries through user input.

## Vulnerable Endpoint
- **URL:** `{url}`
- **Parameter:** `{param}`
- **Method:** GET/POST

## Proof of Concept

### Payload
```sql
{payload}
```

### Steps to Reproduce
1. Navigate to: `{url}`
2. Inject the following SQL payload in the `{param}` parameter:
   ```sql
   {payload}
   ```
3. Observe the application behavior for signs of SQL injection

### Example Request
```http
GET {url}?{param}={payload_encoded} HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (compatible; Security-Test/1.0)
```

## Impact
- Unauthorized database access
- Data extraction and manipulation
- Authentication bypass
- Potential remote code execution
- Complete system compromise

## Risk Rating
**{severity}** - SQL Injection can lead to complete database compromise and sensitive data exposure.

## Remediation
1. Use parameterized queries/prepared statements
2. Implement proper input validation
3. Apply the principle of least privilege for database accounts
4. Use stored procedures where appropriate
5. Implement Web Application Firewall (WAF)
6. Regular security testing and code reviews

## References
- [OWASP SQL Injection Prevention Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)