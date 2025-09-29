# ProwlerMD
A Python script that parses Prowler AWS scan findings from JSON and generates a report in Markdown.

## Project Overview

ProwlerMD is a Python utility that processes AWS Prowler security scan results and generates consolidated Markdown reports. It transforms verbose JSON output from Prowler into readable security reports focused on failed findings with Critical, High, Medium, and Low severity levels.

## Quick Start

### Basic Usage
```bash
python3 ProwlerMD.py <prowler-json-file>
```

### Example
```bash
python3 ProwlerMD.py prowler-output-111111111111-20250928153357.ocsf.json
# Generates: prowler-output-111111111111-20250928153357.ocsf.md
```

### Requirements
- Python 3.x (tested with Python 3.12.8)
- Standard library modules only: `json`, `sys`, `datetime`, `collections`, `pathlib`

## Architecture and Workflow

The script follows a 6-step processing pipeline:

1. **Data Loading** (`load_prowler_data`): Parse Prowler OCSF JSON format
2. **Filtering** (`filter_findings`): Extract only FAIL status findings with target severities
3. **Grouping** (`group_findings_by_title`): Consolidate duplicate findings by CHECK_TITLE
4. **Sorting** (`sort_findings_by_severity`): Order by severity priority (Critical → High → Medium → Low)
5. **Report Generation** (`generate_markdown_report`): Create structured Markdown output
6. **File Writing**: Save report with same name as input, `.md` extension

### Key Data Transformations

The script processes Prowler's OCSF (Open Cybersecurity Schema Framework) JSON format:
- Each finding has `status_code`, `severity`, `finding_info`, `resources`, etc.
- Findings with identical `finding_info.title` are consolidated
- All affected resources are listed under each unique finding
- Output is organized by severity with table of contents

## Core Functions

### `filter_findings(findings)`
Filters for FAIL status with Critical/High/Medium/Low severity. This is the primary filtering logic that determines what appears in the final report.

### `group_findings_by_title(findings)`
Critical function that eliminates duplicate findings by consolidating resources under the same CHECK_TITLE. Uses `defaultdict` with sets to track unique resources and resource types per finding.

### `sort_findings_by_severity(grouped_findings)`
Implements severity ordering with numerical mapping:
- Critical: 1, High: 2, Medium: 3, Low: 4
- Also generates severity counts for executive summary

### `generate_markdown_report(sorted_findings, severity_counts)`
Main report generation with:
- Executive summary with finding counts
- Auto-generated table of contents
- Severity-based sections
- Resource listings in code blocks
- Reference links where available

## Input Format Expectations

ProwlerMD expects Prowler JSON output in OCSF format with these key fields:
```json
{
  "status_code": "FAIL",
  "severity": "High",
  "finding_info": {
    "title": "Check Title"
  },
  "risk_details": "Risk description",
  "remediation": {
    "desc": "Remediation steps"
  },
  "resources": [
    {
      "uid": "resource-identifier",
      "type": "resource-type"
    }
  ],
  "unmapped": {
    "related_url": "reference-url"
  }
}
```

## Output Format

Generated Markdown reports include:
- Executive summary with total findings and severity breakdown
- Table of contents with anchor links
- Findings organized by severity sections
- Each finding shows: title, severity, resource types, risk description, remediation, affected resource count, and resource list
- Reference URLs when available

## File Structure

```
ProwlerMD/
├── ProwlerMD.py                    # Main script - all functionality in single file
├── README.md                       # Basic project description
├── .gitignore                      # Standard Python gitignore
├── LICENSE                         # Project license
└── *.ocsf.json                     # Prowler input files (not committed)
└── *.ocsf.md                       # Generated reports (not committed)
```
