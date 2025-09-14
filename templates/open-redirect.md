# {title}

**Vulnerability Type:** Open Redirect  
**Severity:** {severity}  
**Date:** {date}

## Summary
An Open Redirect vulnerability was discovered that allows attackers to redirect users to malicious external websites.

## Vulnerable Endpoint
- **URL:** `{url}`
- **Parameter:** `{param}`
- **Redirect Target:** `{redirect}`

## Proof of Concept

### Steps to Reproduce
1. Craft a malicious URL: `{url}?{param}={redirect}`
2. Send the link to a victim user
3. User clicks the link and is redirected to the attacker-controlled domain
4. Observe successful redirection to: `{redirect}`

### Example Malicious URL
```
{url}?{param}={redirect}
```

### Expected Behavior
The application should redirect the user to `{redirect}` without proper validation.

## Impact
- Phishing attacks
- Malware distribution
- Social engineering attacks
- Brand reputation damage
- User trust compromise

## Attack Scenarios
1. **Phishing:** Redirect users to fake login pages
2. **Malware:** Redirect to sites hosting malicious software
3. **Social Engineering:** Trick users into visiting attacker-controlled sites

## Risk Rating
**{severity}** - Open redirects facilitate phishing and social engineering attacks.

## Remediation
1. Implement a whitelist of allowed redirect URLs
2. Validate redirect parameters against allowed domains
3. Use relative URLs instead of absolute URLs when possible
4. Implement proper URL validation
5. Log and monitor redirect attempts
6. User education about suspicious links

## References
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)