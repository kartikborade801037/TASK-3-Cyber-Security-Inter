# TASK-3-Cyber-Security-Inter
Task 3 – Basic Vulnerability Scan
Objective:
Use free vulnerability scanning tools like OpenVAS or Nessus Essentials to identify and document common security weaknesses on a computer.

1. Tools Used
OpenVAS or Nessus Essentials – to perform the vulnerability scan

Web browser – for researching vulnerabilities and fixes

2. Steps Followed
Installed and configured OpenVAS / Nessus Essentials.

Set scan target (local system IP, e.g., 192.168.1.x or 127.0.0.1).

Ran a full vulnerability scan and waited for completion.

Reviewed the report, sorted by severity (Critical → Low).

Researched remediation steps for top vulnerabilities.

Documented the findings with examples and suggested fixes.

Saved PDF and HTML reports and added screenshots.

3. Sample Vulnerabilities Found
Severity	Vulnerability	Description	Suggested Fix
Critical	Default/Weak Credentials	Services using default passwords	Change defaults, enforce strong policy
High	Outdated OpenSSH (CVE-XXXX)	Unpatched SSH version	Update to latest version
High	SMBv1 Enabled	Outdated SMB protocol	Disable SMBv1, use SMBv2/3
Medium	Missing Security Updates	System not fully patched	Apply updates regularly
Low	Weak TLS Configuration	Outdated TLS protocols	Enforce TLS 1.2+ with strong ciphers

4. Recommendations
Apply OS and application updates promptly.

Disable unused services and legacy protocols.

Use strong, unique passwords and enable MFA.

Schedule recurring vulnerability scans.

Back up before making major changes.

5. Files in This Repository
vuln_scan_report.pdf – Full PDF report

vuln_scan_report.html – HTML version of the report

screenshots/ – Images of scan results from OpenVAS/Nessus

README.md – This documentation file

6. Interview Questions & Answers
Q: What is vulnerability scanning?
A: Automated detection of known weaknesses in systems.

Q: How often should scans be done?
A: Monthly for critical systems, more often for high-risk networks.

Q: What is CVSS?
A: Common Vulnerability Scoring System — rates severity from 0.0 to 10.0.

✅ This completes Task 3 of the Cyber Security Internship.
