---
title: Review Code-Level Vulnerabilities
keywords:
  - security code review
  - secure coding
  - injection
  - path traversal
  - deserialization
  - code-level analysis
description: A practical guide to reviewing code-level security flaws, from input handling and injection to parser boundaries, sessions, logging, and dangerous functions.
---

## Chapter 4 - Review Code-Level Vulnerabilities

Code-level security analysis is the final layer of the methodology.

The methodology chapter defined structure, modeled subsystem threats, traced data, and checked business logic. This part moves into the code that implements the security controls. The reviewer now asks how individual variables, functions, libraries, parsers, and framework calls can turn attacker-controlled input into security impact.

This chapter is heavier than earlier chapters because code-level review covers many vulnerability families. The goal is not to memorize every bug. The goal is to learn a repeatable pattern: trace the data, identify the trust boundary, find the unsafe assumption, and verify the control.

## Start With Data Flow

Most code-level findings start with data flow.

A reviewer should ask where the data comes from, what code transforms it, and where it is used. The most important question is whether the data is attacker-controlled.

Attacker-controlled input can come from HTTP parameters, headers, cookies, request bodies, uploaded files, JSON fields, URLs, templates, environment-influenced configuration, or messages from another service.

Once the reviewer finds the input, the next question is the sink. A sink is where data becomes meaningful or dangerous. Examples include SQL queries, HTML output, file paths, shell commands, template rendering, XML parsing, object deserialization, logging, and outbound requests.

Code-level review is the path between source and sink.

## Separate Input Validation From Output Encoding

Input validation and output encoding solve different problems.

Input validation checks whether data is acceptable for the application. Output encoding makes data safe for a specific output context, such as HTML.

Stored and reflected XSS show the difference. The application may retrieve a username and place it into the request:

```java
@Override
protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    User user = databaseManager.getUserFromId(request.getParameter("id"));
    request.setAttribute("user", user.getUsername());
    doForward(request, response);
}
```

If the JSP renders that value directly, the browser may treat attacker-controlled text as markup:

```html
<div id="hello-message">
    <p>Hello user <%=request.getAttribute("user")%>. Welcome to the platform!</p>
</div>
```

The safer pattern encodes output for the HTML context:

```jsp
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<div id="hello-message">
    <p>Hello user <c:out value="${requestScope.user}" />. Welcome to the platform!</p>
</div>
```

Client-side validation can still be useful:

```html
<input type="text" id="username" name="username" pattern="[a-zA-Z0-9]{4,20}" required>
```

But client-side validation is not a server-side security control. A reviewer should ask whether the server validates the input and whether the output is encoded for the correct context.

## Review Injection Paths

Injection happens when data changes the meaning of an instruction.

SQL injection is the classic example:

```sql
sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

The issue is not only string concatenation. The issue is that `username` and `password` can become part of the SQL structure. The secure pattern separates query structure from values:

```java
String query = "SELECT * FROM User WHERE username = ? AND password = ?";

PreparedStatement statement = connection.prepareStatement(query);
statement.setString(1, username);
statement.setString(2, passwordHash);

resultSet = statement.executeQuery();
```

Command injection follows the same idea in a different sink:

```java
String[] cmd = { "/bin/sh", "-c", 'ping '+hostname };
Process p = Runtime.getRuntime().exec(cmd);
```

The reviewer should ask whether `hostname` is attacker-controlled. If it is, the code may let the attacker extend the command. The safer review direction is to avoid shell execution when possible. If an external command is required, use strict allowlists and safe process APIs.

Code injection is even more direct:

```java
ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
String expression = "Math.pow(" + x + ",2)" + "+" + y;
engine.eval(expression);
```

Here, the sink is an interpreter. A reviewer should be skeptical whenever user-controlled data reaches `eval`, a scripting engine, dynamic template evaluation, or reflection-based execution.

## Check JSON and Template Boundaries

JSON injection and template injection are boundary problems.

JSON often looks like data, but applications may attach meaning to fields, roles, flags, or object structure. If attackers can add or modify fields, they may influence behavior the developer did not intend.

A reviewer should ask:

- Which fields are allowed?
- Are unknown fields rejected?
- Is the schema enforced?
- Are role, price, owner, or permission fields accepted from the client?

Server-side template injection has a different sink. User input reaches a template engine:

```html
<p th:text="${user_input}"></p>  <!-- Vulnerable if unsanitized -->
```

In Python, direct template construction can create the same risk:

```python
template = Template("Hello {{ " + user_input + " }}")  # Vulnerable
```

Template engines often have access to variables, helpers, or execution features. The reviewer should ask whether user input is treated as content or as template logic.

## Check Parser and Deserialization Boundaries

Parsers turn bytes into structure. That makes them security boundaries.

XML external entity parsing is a clear example:

```xml
<!DOCTYPE route
[
<!ENTITY placeholder SYSTEM "file:///etc/passwd" >
]>
```

If external entities are allowed, XML input may cause the parser to read local files or internal resources. The safer configuration disables dangerous XML features:

```java
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();

dbFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

dbFactory.setXIncludeAware(false);
dbFactory.setExpandEntityReferences(false);
```

The review question is whether the parser accepts untrusted input and whether dangerous features are disabled.

Deserialization has a related risk. It turns input into objects. The reference material recommends safer formats and standard libraries:

```java
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

public class SecureDeserialization {
    public static void main(String[] args) {
        String jsonInput = "{ \"name\": \"John\", \"role\": \"admin\" }";
        Gson gson = new Gson();
        // ...
    }
}
```

The reviewer should ask whether the input is trusted, whether the type is controlled, whether unknown fields are rejected, and whether dependencies are patched.

## Review File, Path, and Temporary File Handling

File access turns strings into filesystem authority.

Path traversal appears when user input controls a filename or path:

```python
file = request.args.get('filename')  # User-provided input
open(f"/var/www/uploads/{file}", "r")  # Potentially vulnerable
```

The secure pattern normalizes the path and checks that it remains inside the allowed directory:

```python
from flask import request, abort
from pathlib import Path

UPLOAD_FOLDER = "/var/www/uploads"

@app.route('/get_file')
def get_file():
    filename = request.args.get('file')
    if not filename:
        abort(400, "File not specified")

    safe_path = Path(UPLOAD_FOLDER).joinpath(filename).resolve()

    if not str(safe_path).startswith(str(Path(UPLOAD_FOLDER).resolve())):
        abort(403, "Access Denied")
    # ...
```

Temporary files need review too. Predictable names can create race conditions:

```python
import os

temp_file = f"/tmp/tempfile_{os.getpid()}.txt"  # Predictable filename
with open(temp_file, "w") as f:
    f.write("Sensitive data")
```

The safer pattern uses secure temporary file APIs and deletes the file when finished:

```python
import tempfile
import os

with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
    temp_file.write("Sensitive data")
    temp_file_path = temp_file.name

os.remove(temp_file_path)
```

The reviewer should check path normalization, base-directory enforcement, permissions, predictable names, cleanup, and time-of-check to time-of-use risk.

## Review Sessions, Tokens, and Authentication Checks

Session and token code should be reviewed at the code level.

The reference material highlights common session risks: predictable session IDs, token exposure, fixation, weak timeouts, missing revocation, missing rotation, XSS, and CSRF.

Secure session code sets protective attributes:

```java
Cookie sessionCookie = new Cookie("JSESSIONID", session.getId());
sessionCookie.setHttpOnly(true);   // Prevents JS access
sessionCookie.setSecure(true);     // HTTPS only
sessionCookie.setPath("/");        // Limits scope
```

JWT review also matters. If signature validation is missing or weak, an attacker may spoof token claims:

```java
Jwts.parser()
    .setSigningKey("secretkey")
    .parseClaimsJws(jwtString).getBody();
```

The reviewer should ask where the signing key comes from, whether the algorithm is fixed, whether expiration is checked, and whether authorization is derived from trusted server-side state.

## Review Request Forgery and Outbound Calls

Request forgery bugs appear when code causes a trusted system to send a request the attacker controls.

CSRF abuses the user's browser and existing session. The reviewer should look for state-changing routes that rely only on cookies and do not require a CSRF token, reauthentication, or another intentional user signal.

SSRF abuses the server. The vulnerable pattern is often an internal request built from user input:

```java
URL url = new URL("http://127.0.0.1" + endpoint);
StringBuilder result = new StringBuilder();
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setRequestMethod("GET");
```

Under normal use, a caller may request `/users/1`. An attacker may try `/secret`, cloud metadata endpoints, localhost-only admin routes, or internal service names.

For SSRF review, denylists are weak. Attackers can bypass simple string checks with redirects, DNS tricks, encoded addresses, alternate IP formats, and internal hostnames. The stronger pattern is an allowlist of known safe destinations and routes.

The reviewer should ask three questions:

1. Can user input control the protocol, host, port, path, or headers?
2. Can the server reach internal networks that the user cannot reach directly?
3. Is the destination restricted by an allowlist before the request is sent?

## Review Error Handling and Logging

Error handling can become data exposure.

This pattern sends internal details to the response:

```java
try {
   // ...
} catch(Exception e) {
   e.printStackTrace(response.getWriter());
}
```

The safer direction is to use controlled error pages and server-side logging:

```xml
<error-page>
   <location>/error.html</location>
</error-page>
```

Logging also needs boundaries. Logs should capture events such as login attempts, authorization failures, input validation failures, administrative activity, and access to sensitive data.

But logs should not contain passwords, session IDs, access tokens, database connection strings, encryption keys, or sensitive personal data. The reviewer should treat logs as a potential data store.

Data exposure also happens through normal application behavior. Passwords and reset tokens should not appear in URLs:

```java
String email = req.getParameter("email");
String password = req.getParameter("password");
```

Username enumeration is another example. If the reset flow says "User does not exist" for one case and "The password reset link has been sent" for another, the application leaks account existence.

The reviewer should check whether external responses reveal more than the user is allowed to know.

## Review Crypto and Dangerous Functions

Cryptographic code should use established libraries and clear purpose.

The source material warns against hardcoded secrets, outdated protocols, custom crypto, and mixing hashing with encryption. Hashing verifies data. Encryption protects confidentiality. They are not interchangeable.

Dangerous functions are review signals:

```text
eval()
```

`eval()` is not always a vulnerability by itself. But it tells the reviewer to ask what input can reach it, what language context it executes in, and whether a safer API exists.

The same principle applies to custom parsing, custom encryption, dynamic inclusion, and framework bypasses. Code-level review should become more skeptical when the implementation reinvents a security-sensitive feature.

## Check Framework Defaults and Insecure Leftovers

Frameworks can reduce risk, but only when their secure defaults are enabled.

The source material calls out examples across Django, Flask, Express.js, Rails, Spring Boot, and Laravel. The specific files differ, but the review questions are stable:

- Are secure cookies enabled?
- Is CSRF protection enabled for browser-facing state changes?
- Are detailed errors disabled in production?
- Are input validation and output escaping handled by framework-supported APIs?
- Are secrets loaded from environment variables or a secret manager?
- Are dependency versions still supported and patched?

Security review should also look for insecure leftovers.

Comments can expose sensitive operations:

```html
<!-- TODO: Change the admin password from the weak password 'adminPass' to something stronger! -->
```

Hardcoded bypasses are worse:

```java
optionalUser.ifPresent(user -> {
    if (this.bCryptUtils.checkPasswordHash(password, user.getPassword()) || "byp@33_p@ssw0rd".equals(password)) {
        HttpSession session = req.getSession();
        session.invalidate();
        // ...
```

Obsolete code, test artifacts, feature flags, and temporary debugging paths often survive longer than expected. A reviewer should ask whether the code is reachable, whether it changes authentication or authorization behavior, and whether it was intended for production.

## Map Findings to Evidence

A code-level finding should produce review evidence.

For each issue, the reviewer should record:

1. What the code is trying to do
2. What input is attacker-controlled
3. What trust boundary is crossed
4. What unsafe assumption exists
5. What impact is possible
6. What safer pattern should replace it

Frameworks such as OWASP Top 10, CWE, CAPEC, MITRE ATT&CK, and CERT can help classify the finding. Classification is useful, but it is not the main goal. The main goal is to explain the risk clearly enough that engineers can fix it.

## Key Takeaway

Code-level security analysis is not random pattern matching.

It is a structured review of how data moves through code and what happens when that data is hostile. The reviewer traces sources to sinks, checks validation and encoding, inspects parser and file boundaries, verifies session and token handling, and treats logging, errors, crypto, and dangerous functions as security-sensitive code.

The next part explains how AI can help scale the same review methodology.

