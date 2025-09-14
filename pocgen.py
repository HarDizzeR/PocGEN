#!/usr/bin/env python3

import argparse
import sys
from datetime import datetime
from pathlib import Path

class POCGenerator:
    def __init__(self):
        self.templates_dir = Path(__file__).parent / 'templates'
        self.supported_types = ['xss', 'sqli', 'cors', 'open-redirect', 'security-headers']
    
    def _load_template(self, vuln_type):
        """Load template from file"""
        template_file = self.templates_dir / f"{vuln_type}.md"
        if not template_file.exists():
            raise FileNotFoundError(f"Template file not found: {template_file}")
        
        return template_file.read_text(encoding='utf-8')
    
    def _extract_host(self, url):
        """Extract hostname from URL"""
        if '://' in url:
            return url.split('://')[1].split('/')[0]
        return url.split('/')[0]
    
    def _format_missing_headers(self, headers):
        """Format missing headers list"""
        if not headers:
            return "- All common security headers are missing or misconfigured"
        
        formatted = []
        for header in headers:
            formatted.append(f"- `{header.strip()}`")
        return '\n'.join(formatted)
    
    def _prepare_template_variables(self, vuln_type, args):
        """Prepare variables for template substitution"""
        variables = {
            'title': args.title,
            'severity': args.severity.upper(),
            'date': datetime.now().strftime('%Y-%m-%d'),
            'url': args.url,
            'host': self._extract_host(args.url)
        }
        
        # Add type-specific variables
        if hasattr(args, 'param') and args.param:
            variables['param'] = args.param
        
        if hasattr(args, 'payload') and args.payload:
            variables['payload'] = args.payload
            # URL encoded version for examples
            variables['payload_encoded'] = (args.payload
                                          .replace(' ', '%20')
                                          .replace('<', '%3C')
                                          .replace('>', '%3E')
                                          .replace("'", '%27'))
        
        if hasattr(args, 'origin') and args.origin:
            variables['origin'] = args.origin
        
        if hasattr(args, 'redirect') and args.redirect:
            variables['redirect'] = args.redirect
        
        if hasattr(args, 'headers') and args.headers:
            variables['headers'] = args.headers
            variables['missing_headers'] = self._format_missing_headers(args.headers.split(','))
        
        return variables
    
    def generate_report(self, vuln_type, args):
        """Generate vulnerability report based on type"""
        if vuln_type not in self.supported_types:
            raise ValueError(f"Unsupported vulnerability type: {vuln_type}")
        
        template = self._load_template(vuln_type)
        variables = self._prepare_template_variables(vuln_type, args)
        
        # Simple template substitution
        try:
            return template.format(**variables)
        except KeyError as e:
            raise ValueError(f"Template variable missing: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Generate Proof of Concept (PoC) reports for security vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pocgen --type xss --url "https://app.example.com/search" --param q --payload "<script>alert(1)</script>" --title "Reflected XSS in search" --severity medium --out poc_xss.md
  pocgen --type sqli --url "https://app.example.com/item" --param id --payload "' OR '1'='1' -- " --title "Potential SQLi in item id" --severity high --out poc_sqli.md
        """
    )
    
    parser.add_argument('--type', required=True, 
                       choices=['xss', 'sqli', 'cors', 'open-redirect', 'security-headers'],
                       help='Type of vulnerability')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--title', required=True, help='Vulnerability title')
    parser.add_argument('--severity', required=True, 
                       choices=['low', 'medium', 'high', 'critical'],
                       help='Vulnerability severity')
    parser.add_argument('--out', required=True, help='Output file name')
    
    # Type-specific arguments
    parser.add_argument('--param', help='Vulnerable parameter (for XSS, SQLi, Open Redirect)')
    parser.add_argument('--payload', help='Exploit payload (for XSS, SQLi)')
    parser.add_argument('--origin', help='Malicious origin (for CORS)')
    parser.add_argument('--redirect', help='Redirect target (for Open Redirect)')
    parser.add_argument('--headers', help='Missing headers comma-separated (for Security Headers)')
    
    args = parser.parse_args()
    
    generator = POCGenerator()
    
    # Validate required arguments for report generation
    if not all([args.type, args.url, args.title, args.severity, args.out]):
        parser.error("--type, --url, --title, --severity, and --out are required for report generation")
    
    # Validate type-specific required arguments
    if args.type in ['xss', 'sqli', 'open-redirect'] and not args.param:
        parser.error(f"--param is required for {args.type}")
    
    if args.type in ['xss', 'sqli'] and not args.payload:
        parser.error(f"--payload is required for {args.type}")
    
    if args.type == 'cors' and not args.origin:
        parser.error("--origin is required for CORS")
    
    if args.type == 'open-redirect' and not args.redirect:
        parser.error("--redirect is required for open-redirect")
    
    try:
        # Generate the report
        report = generator.generate_report(args.type, args)
        
        # Create reports directory if it doesn't exist
        reports_dir = Path('./reports')
        reports_dir.mkdir(exist_ok=True)
        
        # Write to output file in reports directory
        output_path = reports_dir / args.out
        output_path.write_text(report, encoding='utf-8')
        
        print(f"✅ PoC report generated successfully: {output_path}")
        print(f"📄 Report type: {args.type.upper()}")
        print(f"🎯 Target: {args.url}")
        print(f"⚠️  Severity: {args.severity.upper()}")
        
    except FileNotFoundError as e:
        print(f"❌ Template not found: {e}", file=sys.stderr)
        print("💡 Make sure template files exist in the templates/ directory", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error generating report: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()