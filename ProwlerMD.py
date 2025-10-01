#!/usr/bin/env python3
"""
Multi-Cloud Prowler Security Report Generator

This script processes Prowler JSON output and creates a consolidated markdown report
showing only FAIL findings with Critical, High, Medium, and Low severity.
Consolidates duplicate findings by CHECK_TITLE and lists all affected resources.

Supports AWS and Azure cloud providers.
"""

import argparse
import json
import sys
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import os

def load_poc_mappings(poc_file_path):
    """Load and parse the POC mappings JSON file."""
    print(f"Loading POC mappings from {poc_file_path}...")
    try:
        if os.path.exists(poc_file_path):
            with open(poc_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            # Remove metadata for processing, keep only mappings
            mappings = {k: v for k, v in data.items() if not k.startswith('_')}
            print(f"Successfully loaded {len(mappings)} existing POC mappings")
            return data  # Return full data including metadata
        else:
            print("POC mappings file not found, creating new one")
            return {
                "_metadata": {
                    "description": "Mapping of Prowler finding titles to Proof of Concept commands/instructions",
                    "version": "1.0",
                    "last_updated": datetime.now().strftime("%Y-%m-%d")
                }
            }
    except Exception as e:
        print(f"Error loading POC mappings file: {e}")
        sys.exit(1)

def save_poc_mappings(poc_data, poc_file_path):
    """Save the POC mappings JSON file."""
    print(f"Saving POC mappings to {poc_file_path}...")
    try:
        # Update metadata timestamp
        poc_data["_metadata"]["last_updated"] = datetime.now().strftime("%Y-%m-%d")
        with open(poc_file_path, 'w', encoding='utf-8') as f:
            json.dump(poc_data, f, indent=2, ensure_ascii=False)
        mappings_count = len([k for k in poc_data.keys() if not k.startswith('_')])
        print(f"Successfully saved {mappings_count} POC mappings")
    except Exception as e:
        print(f"Error saving POC mappings file: {e}")

def load_prowler_data(json_file_path):
    """Load and parse the Prowler JSON file."""
    print(f"Loading Prowler data from {json_file_path}...")
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"Successfully loaded {len(data)} findings from Prowler output")
        return data
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        sys.exit(1)

def filter_findings(findings):
    """Filter findings to only include FAIL status with Critical/High/Medium severity."""
    print("Filtering findings by status and severity...")
    
    target_severities = {"Critical", "High", "Medium", "Low"}
    filtered = []
    
    for finding in findings:
        # Check for FAIL status
        if finding.get("status_code") != "FAIL":
            continue
            
        # Check for target severity
        severity = finding.get("severity", "")
        if severity not in target_severities:
            continue
            
        filtered.append(finding)
    
    print(f"Filtered to {len(filtered)} findings with FAIL status and Critical/High/Medium/Low severity")
    return filtered

def group_findings_by_title(findings):
    """Group findings by CHECK_TITLE and consolidate resources."""
    print("Grouping findings by CHECK_TITLE and consolidating resources...")
    
    grouped = defaultdict(lambda: {
        'finding': None,
        'resources': set(),
        'resource_types': set()
    })
    
    for finding in findings:
        # Extract the check title
        check_title = finding.get("finding_info", {}).get("title", "Unknown Check")
        
        # Store the first occurrence of this finding for metadata
        if grouped[check_title]['finding'] is None:
            grouped[check_title]['finding'] = finding
        
        # Collect all resource UIDs and types for this check title
        resources = finding.get("resources", [])
        for resource in resources:
            uid = resource.get("uid", "")
            resource_type = resource.get("type", "")
            if uid:
                grouped[check_title]['resources'].add(uid)
            if resource_type:
                grouped[check_title]['resource_types'].add(resource_type)
    
    print(f"Grouped into {len(grouped)} unique findings")
    return grouped

def sort_findings_by_severity(grouped_findings):
    """Sort findings by severity priority: Critical -> High -> Medium -> Low."""
    print("Sorting findings by severity priority...")
    
    severity_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    
    sorted_findings = []
    for check_title, data in grouped_findings.items():
        finding = data['finding']
        severity = finding.get("severity", "Unknown")
        sort_key = (severity_order.get(severity, 99), check_title)
        sorted_findings.append((sort_key, check_title, data))
    
    sorted_findings.sort(key=lambda x: x[0])
    
    # Count findings by severity
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for _, _, data in sorted_findings:
        severity = data['finding'].get("severity", "Unknown")
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    print(f"Severity distribution: {severity_counts}")
    return sorted_findings, severity_counts

def extract_finding_details(finding, resources, resource_types, poc_mappings):
    """Extract and format finding details for the report."""
    title = finding.get("finding_info", {}).get("title", "Unknown Check")
    severity = finding.get("severity", "Unknown")
    risk = finding.get("risk_details", "No risk description available")
    remediation = finding.get("remediation", {}).get("desc", "No remediation information available")
    reference = finding.get("unmapped", {}).get("related_url", "")
    
    # Get POC command from mappings, add title to mappings if not present
    poc_command = ""
    if title in poc_mappings:
        poc_command = poc_mappings[title] if poc_mappings[title] else ""
    else:
        # Add new finding title to mappings with blank value
        poc_mappings[title] = ""
    
    return {
        "title": title,
        "severity": severity,
        "resource_types": sorted(list(resource_types)) if resource_types else ["Unknown"],
        "risk": risk,
        "proof_of_concept": poc_command,
        "remediation": remediation,
        "resources": sorted(list(resources)),
        "reference": reference
    }

def generate_markdown_report(sorted_findings, severity_counts, poc_mappings, provider):
    """Generate the markdown report."""
    print("Generating markdown report...")
    
    report_lines = []
    
    # Header
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_findings = sum(severity_counts.values())
    
    report_lines.extend([
        f"# {provider.upper()} Security Report",
        "",
        f"**Generated:** {current_time}",
        f"**Total Findings:** {total_findings}",
        "",
        "## Executive Summary",
        "",
        f"This report contains {total_findings} security findings from the {provider.upper()} Prowler scan, filtered to show only failed checks with Critical, High, Medium, and Low severity levels.",
        "",
        f"- **Critical Severity:** {severity_counts['Critical']} findings",
        f"- **High Severity:** {severity_counts['High']} findings", 
        f"- **Medium Severity:** {severity_counts['Medium']} findings",
        f"- **Low Severity:** {severity_counts['Low']} findings",
        "",
        "## Table of Contents",
        "",
    ])
    
    # Table of contents
    if severity_counts['Critical'] > 0:
        report_lines.append("- [Critical Severity Findings](#critical-severity-findings)")
    if severity_counts['High'] > 0:
        report_lines.append("- [High Severity Findings](#high-severity-findings)")
    if severity_counts['Medium'] > 0:
        report_lines.append("- [Medium Severity Findings](#medium-severity-findings)")
    if severity_counts['Low'] > 0:
        report_lines.append("- [Low Severity Findings](#low-severity-findings)")
    
    report_lines.append("")
    
    # Generate sections by severity
    current_severity = None
    
    for _, check_title, data in sorted_findings:
        finding = data['finding']
        resources = data['resources'] 
        resource_types = data['resource_types']
        
        details = extract_finding_details(finding, resources, resource_types, poc_mappings)
        
        # Add severity section header if this is a new severity
        if details['severity'] != current_severity:
            current_severity = details['severity']
            severity_anchor = current_severity.lower().replace(' ', '-')
            report_lines.extend([
                f"## {current_severity} Severity Findings",
                ""
            ])
        
        # Add the finding
        report_lines.extend([
            f"### {details['title']}",
            "",
            f"**Severity:** {details['severity']}",
            "",
            f"**Resource Type:** {', '.join(details['resource_types'])}",
            "",
            f"**Risk:** {details['risk']}",
            ""
        ])
        
        # Add Proof of Concept section
        report_lines.extend([
            "**Proof of Concept:**",
            ""
        ])
        
        if details['proof_of_concept']:
            report_lines.extend([
                "```bash",
                details['proof_of_concept'],
                "```"
            ])
        else:
            report_lines.extend([
                "```",
                "# No proof of concept command available",
                "# Manual testing required",
                "```"
            ])
        
        report_lines.extend([
            "",
            f"**Remediation Recommendation:** {details['remediation']}",
            "",
            f"**Affected Resources:** {len(details['resources'])} total",
            ""
        ])
        
        # List all affected resources in a code block
        if details['resources']:
            report_lines.append("```")
            for resource in details['resources']:
                report_lines.append(resource)
            report_lines.append("```")
        else:
            report_lines.append("```")
            report_lines.append("No specific resources identified")
            report_lines.append("```")
        
        report_lines.append("")
        
        # Add reference if available
        if details['reference']:
            report_lines.extend([
                f"**Reference:** {details['reference']}",
                ""
            ])
        
        report_lines.append("---")
        report_lines.append("")
    
    return "\n".join(report_lines)

def main():
    """Main function to process Prowler output and generate report."""
    
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='Multi-Cloud Prowler Security Report Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 ProwlerMD.py --provider aws prowler-output-111111111111-20250928153357.ocsf.json
  python3 ProwlerMD.py -p azure prowler-output-222222222222-20250930120000.ocsf.json
        """)
    
    parser.add_argument(
        'input_file',
        help='Path to the Prowler JSON output file')
    
    parser.add_argument(
        '--provider', '-p',
        required=True,
        choices=['aws', 'azure'],
        help='Cloud provider (aws or azure)')
    
    # Parse arguments
    args = parser.parse_args()
    input_file = args.input_file
    provider = args.provider.lower()
    
    # Validate input file exists
    if not Path(input_file).exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)
    
    # Generate output file path by replacing extension with .md
    input_path = Path(input_file)
    output_file = str(input_path.with_suffix('.md'))
    
    # Set up POC mappings file path based on provider
    script_dir = Path(__file__).parent
    poc_mappings_file = script_dir / f"{provider}_poc_mappings.json"
    
    print(f"Starting {provider.upper()} Prowler Security Report Generation...")
    print("=" * 60)
    
    # Step 0: Load POC mappings
    poc_data = load_poc_mappings(str(poc_mappings_file))
    poc_mappings = {k: v for k, v in poc_data.items() if not k.startswith('_')}
    
    # Step 1: Load the Prowler JSON data
    findings = load_prowler_data(input_file)
    
    # Step 2: Filter for FAIL status with Critical/High/Medium severity
    filtered_findings = filter_findings(findings)
    
    if not filtered_findings:
        print("No findings match the filtering criteria. Report generation complete.")
        return
    
    # Step 3: Group findings by CHECK_TITLE to eliminate duplicates
    grouped_findings = group_findings_by_title(filtered_findings)
    
    # Step 4: Sort findings by severity priority
    sorted_findings, severity_counts = sort_findings_by_severity(grouped_findings)
    
    # Step 5: Generate the markdown report
    report_content = generate_markdown_report(sorted_findings, severity_counts, poc_mappings, provider)
    
    # Step 6: Save updated POC mappings
    poc_data.update(poc_mappings)  # Merge any new findings into poc_data
    save_poc_mappings(poc_data, str(poc_mappings_file))
    
    # Step 7: Write the report to file
    print(f"Writing report to {output_file}...")
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        print(f"Report successfully generated: {output_file}")
        print(f"Total unique findings: {len(sorted_findings)}")
        print("=" * 60)
        print("Report generation complete!")
    except Exception as e:
        print(f"Error writing report file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()