# PocGEN - Proof of Concept Generator

A Python command-line tool for generating professional security vulnerability Proof of Concept (PoC) reports. PocGEN creates standardized, well-formatted markdown reports for common web application security vulnerabilities.

## Features

- 🛡️ **Multiple Vulnerability Types**: Supports XSS, SQL Injection, CORS, Open Redirect, and Security Headers
- 📄 **Template-Based**: Uses customizable markdown templates for consistent reporting
- 🎯 **Professional Output**: Generates detailed PoC reports with impact analysis and remediation steps
- 📊 **Severity Classification**: Supports low, medium, high, and critical severity levels
- 🗂️ **Organized Output**: Automatically saves reports in the `reports/` directory

## Supported Vulnerability Types

| Type | Description | Required Parameters |
|------|-------------|-------------------|
| `xss` | Cross-Site Scripting | `--param`, `--payload` |
| `sqli` | SQL Injection | `--param`, `--payload` |
| `cors` | Cross-Origin Resource Sharing | `--origin` |
| `open-redirect` | Open Redirect | `--param`, `--redirect` |
| `security-headers` | Missing Security Headers | `--headers` |

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd PocGEN
```

2. Ensure Python 3.6+ is installed on your system

3. The tool uses only Python standard libraries, so no additional dependencies are required

## Usage

### Basic Syntax
```bash
python pocgen.py --type <vulnerability-type> --url <target-url> --title <report-title> --severity <severity-level> --out <output-file> [additional-options]
```

### Required Arguments
- `--type`: Vulnerability type (xss, sqli, cors, open-redirect, security-headers)
- `--url`: Target URL
- `--title`: Vulnerability title for the report
- `--severity`: Severity level (low, medium, high, critical)
- `--out`: Output filename (saved in `reports/` directory)

### Type-Specific Arguments
- `--param`: Vulnerable parameter (required for XSS, SQLi, Open Redirect)
- `--payload`: Exploit payload (required for XSS, SQLi)
- `--origin`: Malicious origin (required for CORS)
- `--redirect`: Redirect target URL (required for Open Redirect)
- `--headers`: Comma-separated list of missing headers (for Security Headers)

## Examples

### Cross-Site Scripting (XSS)
```bash
python pocgen.py --type xss --url "https://vulnerable-app.com/search" --param query --payload "<script>alert('XSS')</script>" --title "Reflected XSS in Search Function" --severity high --out test_xss.md
```

### SQL Injection
```bash
python pocgen.py --type sqli --url "https://api.example.com/users" --param user_id --payload "1' UNION SELECT username,password FROM users--" --title "SQL Injection in User Lookup" --severity critical --out test_sqli.md
```

### CORS Misconfiguration
```bash
python pocgen.py --type cors --url "https://api.banking.com/account/balance" --origin "https://malicious-site.com" --title "CORS Allows Any Origin on Banking API" --severity high --out test_cors.md
```

### Open Redirect
```bash
python pocgen.py --type open-redirect --url "https://trusted-site.com/redirect" --param destination --redirect "https://phishing-site.com/fake-login" --title "Open Redirect in Authentication Flow" --severity medium --out test_redirect.md
```

### Missing Security Headers
```bash
python pocgen.py --type security-headers --url "https://webapp.company.com" --headers "Strict-Transport-Security,X-Frame-Options,Content-Security-Policy,X-Content-Type-Options" --title "Missing Critical Security Headers" --severity low --out test_headers.md
```

## Output Structure

Generated reports include:
- **Vulnerability Summary**: Type, severity, and date
- **Vulnerable Endpoint**: URL, parameters, and HTTP methods
- **Proof of Concept**: Step-by-step reproduction steps
- **Example Requests**: HTTP request samples with payloads
- **Impact Analysis**: Potential security implications
- **Risk Rating**: Detailed severity assessment
- **Remediation Steps**: Actionable mitigation recommendations
- **References**: Links to relevant security resources (OWASP, CWE)

## Directory Structure

```
PocGEN/
├── pocgen.py           # Main application
├── README.md           # This file
├── templates/          # Vulnerability report templates
│   ├── xss.md
│   ├── sqli.md
│   ├── cors.md
│   ├── open-redirect.md
│   └── security-headers.md
└── reports/            # Generated PoC reports (auto-created)
    ├── test_xss.md
    ├── test_sqli.md
    ├── test_cors.md
    ├── test_redirect.md
    └── test_headers.md
```

## Customization

### Template Modification
Templates are located in the `templates/` directory. Each template uses placeholder variables that are automatically replaced with provided values:

- `{title}` - Report title
- `{severity}` - Severity level
- `{date}` - Current date
- `{url}` - Target URL
- `{host}` - Extracted hostname
- `{param}` - Vulnerable parameter
- `{payload}` - Exploit payload
- `{payload_encoded}` - URL-encoded payload
- `{origin}` - CORS origin
- `{redirect}` - Redirect target
- `{headers}` - Missing headers list

### Adding New Vulnerability Types
1. Create a new template file in `templates/`
2. Add the new type to `supported_types` in `pocgen.py`
3. Update the argument parser choices
4. Add any type-specific validation logic

## Error Handling

The tool provides clear error messages for:
- Missing required arguments
- Invalid vulnerability types
- Missing template files
- File write permissions
- Template variable mismatches

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add new templates or improve existing ones
4. Test with various inputs
5. Submit a pull request

## License

This tool is designed for legitimate security testing and educational purposes only. Always ensure you have proper authorization before testing applications.

## Changelog

- **v1.0**: Initial release with support for 5 vulnerability types
- Template-based report generation
- Automatic output organization
- Comprehensive error handling