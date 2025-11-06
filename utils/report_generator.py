"""Report Generation Module"""

import json
from datetime import datetime
from colorama import Fore, Style

class ReportGenerator:
    def __init__(self, target_url, scan_results, elapsed_time):
        self.target_url = target_url
        self.scan_results = scan_results
        self.elapsed_time = elapsed_time
    
    def generate_console_report(self):
        """Generate console-friendly report"""
        report = f"\n{Fore.CYAN}📊 SCAN REPORT"
        report += f"\n{Fore.CYAN}{'='*50}"
        report += f"\n{Fore.WHITE}Target: {Fore.YELLOW}{self.target_url}"
        report += f"\n{Fore.WHITE}Scan Time: {Fore.YELLOW}{self.elapsed_time:.2f} seconds"
        report += f"\n{Fore.WHITE}Date: {Fore.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        report += f"\n{Fore.CYAN}{'-'*50}"
        
        total_vulnerabilities = 0
        for scan_type, results in self.scan_results.items():
            count = len(results)
            total_vulnerabilities += count
            
            status_color = Fore.RED if count > 0 else Fore.GREEN
            status_icon = "❌" if count > 0 else "✅"
            
            report += f"\n{Fore.WHITE}{scan_type.replace('_', ' ').title()}: {status_color}{count} vulnerabilities {status_icon}"
        
        report += f"\n{Fore.CYAN}{'-'*50}"
        report += f"\n{Fore.WHITE}Total Vulnerabilities: {Fore.RED if total_vulnerabilities > 0 else Fore.GREEN}{total_vulnerabilities}"
        
        # Detailed findings
        if total_vulnerabilities > 0:
            report += f"\n\n{Fore.RED}🔍 DETAILED FINDINGS:"
            for scan_type, results in self.scan_results.items():
                for vuln in results:
                    report += f"\n{Fore.RED}• {vuln['type']}: {vuln.get('parameter', vuln.get('header', 'N/A'))}"
        
        return report
    
    def generate_json_report(self):
        """Generate JSON report"""
        report = {
            'scan_metadata': {
                'target': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'scan_duration': self.elapsed_time,
                'scanner_version': '1.0.0'
            },
            'results': self.scan_results,
            'summary': {
                'total_vulnerabilities': sum(len(results) for results in self.scan_results.values())
            }
        }
        return json.dumps(report, indent=2)
    
    def generate_html_report(self):
        """Generate HTML report"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {self.target_url}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .vulnerability {{ background: #ffe6e6; padding: 10px; margin: 10px 0; }}
                .safe {{ background: #e6ffe6; padding: 10px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <h1>🔍 Web Security Scan Report</h1>
            <p><strong>Target:</strong> {self.target_url}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Scan Duration:</strong> {self.elapsed_time:.2f} seconds</p>
            
            <h2>Results</h2>
            {self._generate_html_results()}
        </body>
        </html>
        """
    
    def _generate_html_results(self):
        """Generate HTML results section"""
        html = ""
        for scan_type, results in self.scan_results.items():
            html += f"<h3>{scan_type.replace('_', ' ').title()}</h3>"
            if results:
                for vuln in results:
                    html += f'<div class="vulnerability"><strong>{vuln["type"]}</strong><br>{vuln.get("evidence", "No details")}</div>'
            else:
                html += '<div class="safe">No vulnerabilities found</div>'
        return html
