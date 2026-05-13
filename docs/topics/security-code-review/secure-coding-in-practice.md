---
title: Secure Coding in Practice
keywords:
  - secure code review
  - secure coding
  - application security
description: Secure coding notes reformatted from source text into Markdown.
---

## Secure Coding in Practice

## Source Outline

- Secure Coding Guidance
  - Input Validation & Parsing
    - Summary
    - Stored XSS
    - Reflected XSS
    - SQL Injection
    - Command Injection & Code Injection
    - JSON Injection
    - Java: Dynamic JSP Inclusion (Similar to XEE)
    - XML External Entities (XEE) Parsing
    - Template Injection: Server-side Template Injection (SSTI)
    - Path Traversal
    - Client-side Validation
  - Secure Cryptographic Practices for Developers
    - Overview
    - 1. Loading Secrets Securely
    - 2. Choosing the Correct Protocol
    - 3. Using HTTPS with Certificate Confirmation
    - 4. Do Not Mix Hashing and Encryption
    - 5. Do Not Reinvent Decryption Methods
    - 6. Protect Sensitive Data in Transit and at Rest
    - Summary
  - CSRF: Cross-Site Request Forgery
  - SSRF: Server-Side Request Forgery
  - Broken Session Management
    - What is Session Management?
    - Common Causes & Mitigation
    - Java Example — Secure Session Management
    - Python Flask Example — Secure Session Management
    - JWT Security
  - Broken Access Control
    - Insecure Authentication and Authorization
    - Broken Password Lifecycle
      - 1. Initial Password Setup
      - 2. Password Change
      - 3. Broken Password Reset
      - 4. Additional Fortification of Password: Multi-Factor Authentication (MFA)
      - Summary
    - Forced Browsing (missing authorization confirmation check)
    - Insecure Direct Object References (IDOR)
  - Data Exfiltration
    - Default Error Page and StackTrace Logging
    - Exfiltration via GET Request: URL Parameters
    - Exfiltration via Response (Username Enumeration)
    - Exfiltration via Server Side Internal & Egress Request
  - Secure File and Path handling (path traversal attack)
    - Secure Temporary Files
    - Secure File Parsing
    - Secure File Path Handling
    - Secure File Uploading
  - Secure by Default with Framework Dependency
  - Insecure Coding Practice
    - Security Sensitive Code Comments
    - Hardcoded Secrets
    - Cookies Configuration
    - Obsolete Code
    - Dangerous Function
    - Non-standard practice (re-invent the wheel)
    - Secure Serialization and Deserialization
      - Best Practices for Secure Deserialization:
      - Example — Secure JSON Parsing in Java with GSON:
      - Key Takeaways:
      - Encryption and Decryption
  - Secure Logging
    - What events need to be logged
    - What should not be logged
    - Logging levels
  - Software Supply Chain, OSS, and SBOM

<!-- The source text contained the outline twice before the body. The repeated outline was not duplicated here. -->

## Secure Coding Guidance

### Input Validation & Parsing

#### Summary

- via HTTPRequest: User input string sanitization: escape HTML content: string → UserName, password, via regular expression

- Sanitization matches any IPv4 address:  /^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$/

#### Stored XSS

XSS is a client-side injection attack typically seen in applications where user input is displayed in the HTML output of a page. Examples include profile pages, search pages, and comments pages.

If unsanitized, unencoded input is generated as part of a page's output, an attacker can use JavaScript to execute malicious code when the page loads. This can be used to steal sessions or sensitive data from cookies and rewrite elements in the page.

Insecure Code
```java
@Override
protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    User user = databaseManager.getUserFromId(request.getParameter("id"));
request.setAttribute("user", user.getUsername());
doForward(request, response);
}
```

Secured Code (with input validation and Sanitization)

Sanitizing method: Regular expression lib.
```java
@Override
protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    User user = databaseManager.getUserFromId(request.getParameter("id"));
    String username = user.getUsername();
  if (validUserName(username)) {
      request.setAttribute("user", username);
      doForward(request, response);
  } else {
      response.setStatus(400);
  }
}

private Boolean validUserName(String username) {
    Pattern pattern = Pattern.compile("^[a-zA-Z0-9]+$");
    Matcher matcher = pattern.matcher(username);
    return matcher.find();
}
```

Client-side input validation: not fully secured, as client-side data should never be trusted without server-side validation and sanitization
```html
<input type="text" id="username" name="username" pattern="[a-zA-Z0-9]{4,20}" required>
```

Output encoding

The Java Standard Tag Library (JSTL) provides the <c:out> tag, which will HTML encode content by default. This should be used when displaying content to users.
```jsp
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core " %>
<div id="hello-message">
    <p>Hello user <c:out value="${requestScope.user}" />. Welcome to the platform!</p>
</div>
```

#### Reflected XSS

XSS is a client-side injection attack typically seen in applications where user input is displayed in the HTML output of a page. Examples include profile pages, search pages, and comments pages.

If unsanitized, unencoded input is generated as part of a page's output, an attacker can use JavaScript to execute malicious code when the page loads. This can be used to steal sessions or sensitive data from cookies and rewrite elements on the page.

In some cases, cross-site request forgery (CSRF) attacks may be possible where XSS is used to perform requests that the user never intended.

Vulnerable Code: Java, JSP/JSTL
```java
@Override
protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    User user = databaseManager.getUserFromId(request.getParameter("id"));

    request.setAttribute("user", user.getUsername());
    doForward(request, response);
}
```

Corresponding JSP Code
```html
<div id="hello-message">
    <p>Hello user <%=request.getAttribute("user")%>. Welcome to the platform!</p>
</div>
```

Or Corresponding JSTL Code
```html
<div id="hello-message">
    <p>Hello user ${requestScope.user}. Welcome to the platform!</p>
</div>
```

Secure Code (Input validation and sanitization)
```java
@Override
protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    User user = databaseManager.getUserFromId(request.getParameter("id"));
    String username = user.getUsername();

    if (validUserName(username)) {
        request.setAttribute("user", username);
        this.doForward(request, response);
    } else {
        response.setStatus(400);
    }
}

private Boolean validUserName(String username) {
    Pattern pattern = Pattern.compile("^[a-zA-Z0-9]+$");
    Matcher matcher = pattern.matcher(username);

    return matcher.find();
}
```

Secure Code: JSP Code with Regex Filtering
```html
<input type="text" id="username" name="username" pattern="[a-zA-Z0-9]{4,20}" required>
```

Secure Code: JSTL with filtering

The Java Standard Tag Library (JSTL) provides the <c:out> tag, which will HTML encode content by default. This should be used when displaying content to users.
```jsp
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<div id="hello-message">
    <p>Hello user <c:out value="${requestScope.user}" />. Welcome to the platform!</p>
</div>
```

#### SQL Injection

SQLi flaws occur when data from a user is included without first being sanitized or filtered for known values.

If unvalidated, unsanitized input from a user or system is used to form part of the SQL query, an attacker can use it to modify the SQL query itself and execute malicious SQL queries against the database. This could include queries to modify or add data, bypass business logic (such as bypassing authentication), or even execute commands directly on the database server.

Insecure Code:
```sql
sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

Secure Code: (Always use prepared statement):
```java
String query = "SELECT * FROM User WHERE username = ? AND password = ?";

PreparedStatement statement = connection.prepareStatement(query);
statement.setString(1, username);
statement.setString(2, passwordHash);

resultSet = statement.executeQuery();
```

Additional note for Input sanitization

A handful of special characters and sequences are typically used in SQLi attacks. These include, but are not limited to, the following: ', ",;, –, and #. Creating a list of forbidden characters, known as a denylist, would seem like a good way to combat this, but attackers can use numerous methods to bypass these restrictions. Instead, user input should be sanitized against a list of allowed characters, which can be done using built-in string functions or regular expressions.
#### Command Injection & Code Injection

Command injection vulnerabilities arise when a developer executes an external command with a parameter that the user controls.

Vulnerable Code
```java
String[] cmd = { "/bin/sh", "-c", 'ping '+hostname };
Process p = Runtime.getRuntime().exec(cmd);
```

Remediation:

- The first step in remediating command injection attacks should be to reduce the attack surface by removing unnecessary calls to external commands.

- Where external commands must be used, it's essential to use Java's safer functions and libraries to handle the interactions. One method is to create an allowlist of possible values and ensure the user-supplied data matches one in this list

Code injection is similar to command injection, but it's different. In code injection, the attacker can inject code that the application executes. They can potentially perform any action supported by the injected code language.

In command injection, an attacker extends the application's existing functionality. The application already executes system commands, and the attacker then injects commands into this pre-existing functionality.

Vulnerable Code: (Java code calls JavaScript engine for code execution)
```java
ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
String expression = "Math.pow(" + x + ",2)" + "+" + y;
engine.eval(expression);
```

#### JSON Injection

Improper handling and validation of JavaScript Object Notation (JSON) objects can lead to JSON injection vulnerabilities. Attackers can modify JSON data to add additional fields, allowing them control over the application or giving access that the developers did not intend.

Input sanitization

A handful of unique characters and sequences are used in a variety of injection-oriented attacks. These include, but are not limited to, ', ",;,—, and #. Creating a list of forbidden characters, known as a denylist, would seem like an excellent way to combat this, but attackers can use numerous methods to bypass these restrictions. Instead, user input should be sanitized against a list of allowed characters, which can be done using built-in string functions or regular expressions.

Regular expressions

If user input needs to be part of the query, you can perform checks to ensure the user string matches the expected content. You can also use pattern-matching techniques, such as regular expressions, to ensure user-provided input matches an expected format.

Detection

Due to the complexity of JSON injection vulnerabilities, it can be difficult for a scanner to detect when these issues occur. One method to test for this flaw is to include a series of automated test cases as part of the QA or deployment process.

Regular penetration testing and peer reviews are also fundamental to identify vulnerabilities

#### Java: Dynamic JSP Inclusion (Similar to XEE)

Insecure inclusion:
```jsp
<jsp:include page="pages/${param.page}.jsp"/>
```

#### XML External Entities (XEE) Parsing

An XML document may optionally contain a document type definition (DTD) that defines how the document is structured and which elements and attributes are valid.

As part of DTDs, we can define entities, a way of declaring an identifier with a value and having it referenced in a document:
```xml
<!DOCTYPE route
[
<!ENTITY placeholder SYSTEM "file:///etc/passwd" >
]>
```

Any use of &amp;placeholder in the XML document would then be replaced with the contents of the /etc/passwd file.

Insecure Way to Handle XML Parsing

The code below disables commonly problematic features relating to external entities, parameter entities, and loading external DTDs.
```java
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();

dbFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

dbFactory.setXIncludeAware(false);
dbFactory.setExpandEntityReferences(false);
```

Secure Parsing:

```java
dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

Alternatively, it's worth considering using a less complex data structure, such as JSON, that does not permit external entities.
#### Template Injection: Server-side Template Injection (SSTI)

Passing unsanitized user input into templating engines can lead to server-side template injection (SSTI) vulnerabilities. Attackers can craft specialized payloads that allow them to execute code on the server.

In Java, the Thymeleaf templating engine generates HTML pages with server-side data.

Vulnerable code in Java:
```html
<p th:text="${user_input}"></p>  <!-- Vulnerable if unsanitized -->
```

Secure Solution (Regex Filtering)
```java
 @GetMapping({"", "/", "/home", "/landing", "/dashboard", "/feed"})
 public String home(final AuthDTO authDTO, final Model model) {
   if (!validUserName(authDTO.getUsername())) {
       return "redirect:/error";
   }
   model.addAttribute(KEY_USER, authDTO);
   model.addAttribute("questions", questionAndAnswerService.getAllQuestions());
   return "feed";
 }
 private Boolean validUserName(String username) {
   Pattern pattern = Pattern.compile("^[a-zA-Z0-9]+$");
   Matcher matcher = pattern.matcher(username);
   return matcher.find();
 }
```

Vulnerable Code in Python: Jinja2:
```python
template = Template("Hello {{ "world" }}")  # Safe
template = Template("Hello {{ " + user_input + " }}")  # Vulnerable
```

How to Mitigate SSTI:

- Never trust user input in templates.

- Use template sandboxing or escaping functions.

- Employ input validation and proper sanitization.

- Avoid rendering raw input directly in server-side templates.

#### Path Traversal

Path (or directory) traversal vulnerabilities allow threat actors to view file contents they should not be able to. They are usually found in functions enabling users to request files directly, primarily when adequate safety checks are not implemented.

Vulnerable Code:
```python
file = request.args.get('filename')  # User-provided input
open(f"/var/www/uploads/{file}", "r")  # Potentially vulnerable
```

```java
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        String filename = req.getParameter("filename");

        if (filename == null) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // Get the base path where all avatar live
        String basePath = req.getServletContext().getRealPath("avatar");

        // Join this with the provided filename
        Path path = Paths.get(basePath, filename);

        File file = path.toAbsolutePath().toFile();

        if (!file.exists()) {
            // File doesn't exist
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        // Return the file
        try (InputStream in = new FileInputStream(file);
             OutputStream out = resp.getOutputStream()) {

            byte[] buffer = new byte[1024];

            int numBytesRead;
            while ((numBytesRead = in.read(buffer)) > 0) {
                out.write(buffer, 0, numBytesRead);
            }
        }

    }
```

Common Path Traversal Patterns

- Concatenating user input with file paths.

- Trusting unvalidated user input for file operations.

- Not properly sanitizing or normalizing file paths.

- Lack of restriction on allowed directories.

Mitigation Methods:

- Input Validation: Ensure user input strictly matches the expected format (e.g., filename with a specific extension).

- Path Normalization: Normalize paths to resolve ../ or ./ to avoid directory traversal.

- Use Whitelisting: Only allow specific directories or filenames to be accessed.

- Use a Secure API: Utilize high-level libraries or functions that abstract away low-level file handling.

- Implement Permission Checks: Verify file permissions before reading or writing to a file.

Secure Code (Python)
```python
from flask import request, abort
from pathlib import Path

UPLOAD_FOLDER = "/var/www/uploads"
@app.route('/get_file')
def get_file():
    filename = request.args.get('file')
    if not filename:
        abort(400, "File not specified")

    # Normalize path to avoid traversal
    safe_path = Path(UPLOAD_FOLDER).joinpath(filename).resolve()

    # Ensure the file is within the upload folder
    if not str(safe_path).startswith(str(Path(UPLOAD_FOLDER).resolve())):
        abort(403, "Access Denied")
    # Open and read file securely
    try:
        with safe_path.open('r') as file:
            return file.read()
    except FileNotFoundError:
        abort(404, "File not found")
```

Secured Code (Java)
```java
import java.io.*;
import javax.servlet.http.*;
import javax.servlet.annotation.WebServlet;

@WebServlet("/getFile")
public class SecureFileServlet extends HttpServlet {
    private static final String BASE_DIR = "/var/www/uploads/";

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        if (fileName == null || fileName.contains("..")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file name");
            return;
        }

        File file = new File(BASE_DIR, fileName);
        String canonicalPath = file.getCanonicalPath();
        String baseCanonicalPath = new File(BASE_DIR).getCanonicalPath();

        if (!canonicalPath.startsWith(baseCanonicalPath)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
            return;
        }

        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = fis.readAllBytes();
            response.getOutputStream().write(data);
        } catch (FileNotFoundException e) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File Not Found");
        }
    }
}
```

Summary of Best Practices

- Never trust user input for file paths.

- Always normalize and validate file paths.

- Use secure APIs and abstract file handling.

- Implement strict directory access policies.

- Log suspicious file access attempts.

Mitigating path traversal is critical for maintaining the confidentiality and integrity of sensitive files. Proper validation, normalization, and security checks ensure attackers cannot exploit directory structures.
#### Client-side Validation

Modern web applications often use client-side validations in HTML or JavaScript to check the accuracy of the data. However, attackers can easily bypass client-side validations using only a web browser. So, while these client-side validations can deliver a good user experience, all critical validations should be performed server-side. This type of vulnerability is classified as a business logic flaw.

### Secure Cryptographic Practices for Developers

#### Overview

Security in software development is paramount, particularly when handling sensitive data. Cryptographic practices ensure confidentiality, integrity, and authenticity. This document outlines essential cryptographic concepts, best practices, and common pitfalls for developers. Code samples in Python and Java are provided where applicable.
#### 1. Loading Secrets Securely

Sensitive data such as encryption keys, passwords, and tokens should never be hardcoded. Instead, load these secrets from secure environment files or secret management services.

Python Example:
```python
import os
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("Missing secret key!")
```

Java Example:
```java
String secretKey = System.getenv("SECRET_KEY");
if (secretKey == null) {
    throw new RuntimeException("Missing secret key!");
}
```

#### 2. Choosing the Correct Protocol

Use standardized, secure protocols for communication and data transfer. Avoid legacy or outdated protocols.

Best Practices:

- Use TLS 1.2 or TLS 1.3 for secure communication.

- Avoid SSL and older versions of TLS.

#### 3. Using HTTPS with Certificate Confirmation

HTTPS ensures encrypted communication, but verifying certificates adds authenticity to the connection.

Python Example:
```python
import requests
response = requests.get('https://example.com', verify='/path/to/cert.pem')
```

Java Example:
```java
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> hostname.equals("example.com"));
```

#### 4. Do Not Mix Hashing and Encryption

Hashing and encryption serve different purposes. Hashing is one-way (for verification), while encryption is two-way (for confidentiality).

Incorrect (Mixing):
```python
import hashlib
hashlib.sha256(encrypt(data))

Correct (Separate Purposes):
hashed = hashlib.sha256(data).hexdigest()
encrypted = encrypt(data)
```

#### 5. Do Not Reinvent Decryption Methods

Always use established, tested cryptographic libraries. Custom decryption methods often introduce vulnerabilities.

Python Example:
```python
from cryptography.fernet import Fernet
key = Fernet.generate_key()
cipher = Fernet(key)
encrypted = cipher.encrypt(b"Sensitive Data")
decrypted = cipher.decrypt(encrypted)
```

Java Example:
```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecretKey key = KeyGenerator.getInstance("AES").generateKey();
// ...
```

#### 6. Protect Sensitive Data in Transit and at Rest

Always ensure sensitive data is encrypted both when stored and during transmission.

At Rest:
```python
with open('secret.dat', 'wb') as f:
    f.write(encrypt(data))
```

In Transit:
```java
HttpsURLConnection conn = (HttpsURLConnection) new URL("https://example.com").openConnection();
conn.setSSLSocketFactory(sslContext.getSocketFactory());
```

#### Summary

Proper cryptographic practices are essential for secure software development. Following best practices, using established libraries, and adhering to secure protocols protect sensitive data from potential vulnerabilities. Avoiding common pitfalls such as mixing hashing and encryption or hardcoding sensitive data will significantly improve the security posture of any application.
### CSRF: Cross-Site Request Forgery

Cross-Site Request Forgery (CSRF) is a type of attack that relies on tricking a user into performing an unintended action within an application they're logged into.

- Vulnerability: Attackers often use social engineering techniques to direct a victim to a malicious ‘spoof’ web page, which is then used to request a legitimate website.

- Impact: This attack can be used to perform a range of state-changing requests, such as transferring funds to an alternative account or changing user details to redirect goods or information.

- Remediation: It's recommended to utilize built-in or existing CSRF Implementations for CSRF Protection. It is also essential to implement user reauthentication or CAPTCHA for high-risk requests.

### SSRF: Server-Side Request Forgery

Server-side request forgery (SSRF) can allow attackers access to internal systems, potentially letting them interact with sensitive data and prohibited functionality. You should make appropriate checks when allowing user data within server-side requests to prevent this.

- Vulnerability: When unfiltered user-specified server requests are allowed, attackers may be able to access private resources within an application by forcing the application to retrieve them.

- Impact: Applications that are vulnerable to SSRF can allow sensitive data and even administrative functionality to be accessed by attackers, impacting the application's function and user privacy severely.

Vulnerable code (Java):
```java
URL url = new URL("http://127.0.0.1" + endpoint);
StringBuilder result = new StringBuilder();
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setRequestMethod("GET");
try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
    for (String line; (line = reader.readLine()) != null;) {
        result.append(line);
    }
}
```

Under normal circumstances, users will request an intended endpoint.
```text
POST data: {"endpoint" : "/users/1"}
# Result: '{"username" : "user"}'

Attackers can control the endpoint data in the POST request to access endpoints otherwise blocked by external hosts.
POST data: {"endpoint" : "/secret"}
# Result: '{"secret_key" : "a092fb8ab2c2"}'
```

Remediation

When allowing user input within internal web requests, you should always check to ensure that private resources can't be accessed.

One method is to implement an allowlist, restricting the user's endpoints to only those considered safe.

Another method is to implement a denylist, discarding any requests from a user that attempt to access local resources or sensitive URIs. However, this could be bypassed, unlike an allowlist. It also runs the risk of not being comprehensive enough.

### Broken Session Management

#### What is Session Management?

Session management is the process of securely handling user interactions with a system by creating, maintaining, and terminating sessions. It ensures proper authentication, secure token handling, timeout policies, and session revocation. Poor session management can lead to session hijacking, fixation, or impersonation attacks.
#### Common Causes & Mitigation

| Cause | Description | Mitigation |
| --- | --- | --- |
| Insecure Session ID (SID) | Predictable or sequential IDs. | Use cryptographically secure random tokens. |
| Session ID Exposure | Token leakage via URLs or HTTP. | Use HTTPOnly, Secure, SameSite cookies. |
| Session Fixation | Reusing the session ID after authentication. | Regenerate session ID upon login. |
| Weak Timeout Policies | No inactivity or absolute timeout. | Implement short idle timeouts (e.g., 15 min). |
| Improper Token Revocation | Token remains valid after logout or changes. | Revoke tokens immediately on logout. |
| Lack of Token Rotation | Using the same token across multiple sessions. | Rotate tokens on privilege change. |
| XSS Vulnerabilities | Stealing tokens via scripts. | Use CSP, input validation, and HttpOnly. |
| CSRF Attacks | Token hijacking via CSRF attacks. | Implement CSRF protection tokens. |

#### Java Example — Secure Session Management

```java
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        HttpSession session = request.getSession();

        // Set Secure Attributes
        session.setAttribute("user", "john.doe");
        session.setMaxInactiveInterval(900); // 15 minutes timeout

        Cookie sessionCookie = new Cookie("JSESSIONID", session.getId());
        sessionCookie.setHttpOnly(true);   // Prevents JS access
        sessionCookie.setSecure(true);     // HTTPS only
        sessionCookie.setPath("/");        // Limits scope

        response.addCookie(sessionCookie);
        response.sendRedirect("dashboard.jsp");
    }
}
```

##### Key Takeaways

- setHttpOnly(true): Protects cookies from XSS.

- setSecure(true): Ensures transmission over HTTPS.

- setMaxInactiveInterval(900): Limits session duration.

#### Secure Code: Session Fixation

Using the correct session configurations within web.xml is generally enough to prevent the modification or persistence of sessions. The snippet below shows how valid cookie configurations can remediate session fixation vulnerabilities:
```xml
    <session-config>
     <cookie-config>
         <http-only>true</http-only>
         <secure>true</secure>
     </cookie-config>
     <tracking-mode>COOKIE</tracking-mode>
   </session-config>
```

In Java, sessions can be further secured by using HttpSession's request.getSession() function:
```java
HttpSession session = request.getSession();
```

Passing true as a parameter into the request.getSession() method would retrieve the current session on the page, and, assuming one does not yet exist, a new session would be created.

#### Python Flask Example — Secure Session Management

```python
from flask import Flask, session, redirect, url_for, request, make_response
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure random session key

@app.route('/login', methods=['POST'])
def login():
    # Validate user credentials
    if request.form['username'] == 'admin' and request.form['password'] == 'password':
        session['user'] = request.form['username']
        response = make_response(redirect(url_for('dashboard')))

        # Set Secure Cookie
        response.set_cookie('session', session.sid,
                             httponly=True, secure=True, samesite='Lax')
        return response
    return "Invalid credentials", 401

@app.route('/logout')
def logout():
    session.clear()  # Invalidate session
    return "Logged out", 200

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return f"Welcome {session['user']}!"
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(ssl_context='adhoc')  # Enables HTTPS
```

##### Key Takeaways

- os.urandom(24): Strong random session key.

- session.clear(): Immediate session invalidation.

- secure=True: Ensures HTTPS transmission.

#### Conclusion

Implementing proper session management is crucial to secure web applications. Developers can mitigate common vulnerabilities such as session fixation, XSS, and CSRF by using secure cookies, setting timeouts, and properly revoking tokens.
#### JWT Security

Invalid Signature:

- Vulnerability: When the JWT signature check is missing, an attacker is able to spoof arbitrary data in the JWT.

- Fix the Signing Key

```java
Jwts.parser()
    .setSigningKey("secretkey")
    .parseClaimsJws(jwtString).getBody();
```

### Broken Access Control

#### Insecure Authentication and Authorization

Robust authentication and authorization mechanisms are essential for the secure operation of any application. Improper validation can allow users to bypass access controls, impersonate other users, or gain unauthorized access to sensitive information.

In code implementation and review, authentication is typically a two-step process:

- Verifying the existence of the username, often by checking a database.

- Validating the password, where the user-submitted password is compared against a stored hash, sometimes a salted hash, to ensure authenticity.

However, authentication alone is insufficient. While authentication confirms the user's identity, it does not determine what resources the user is authorized to access. This is where many developers make mistakes. Proper authorization must follow authentication to verify whether the user has the necessary permissions to access the intended data or perform specific actions.

At a minimum, three levels of access permissions should be enforced:

- Internal Public: Accessible to all authenticated users.

- Personal Data: Restricted to the data owner for viewing and editing.

- Admin/Restricted Data: Limited to a select group with elevated privileges for viewing and editing.

Authorization is a crucial step that should not be overlooked. Code should explicitly verify user permissions before performing sensitive operations. Failing to implement proper authorization checks can result in severe security vulnerabilities.

In practice, it is highly recommended that clear comments in the code highlight the specific processes of authentication and authorization. This improves code maintainability and ensures future developers understand the security measures.
#### Broken Password Lifecycle

The user password lifecycle is a critical security feature for all systems. Vulnerabilities in password lifecycle management often stem from improper user validation and authentication prior to any meaningful account operation. This document outlines key stages, security risks, best practices, and code review focus points.
##### 1. Initial Password Setup

Security Risk: When a user account is first created, the initial password should never be stored in plain text. Storing plain text passwords poses a severe security risk if the database is compromised. Even hashing passwords with weak or unsalted algorithms makes them susceptible to brute force attacks.

Best Practices:

- Always hash passwords using strong algorithms such as bcrypt, Argon2, or at least SHA-256 with salt/pepper.

- Force users to change system-generated initial passwords upon first login.

Code Review Focus:

- Verify that passwords are never logged or stored in plain text.

- Ensure the hashing function is implemented securely with unique salts.

- Check for proper error handling to avoid revealing sensitive information.

- Common Mistake: Developers sometimes log sensitive data for debugging purposes or use outdated hashing algorithms.

##### 2. Password Change

Security Risk: Improperly implemented password change mechanisms may allow users to modify other accounts or bypass validation checks. Without robust authentication, attackers can exploit this to compromise accounts.

Best Practices:

- Require current password verification before allowing a password change.

- Enforce strong password policies (length, complexity, and reuse restrictions).

- Log and monitor password change attempts for anomalies.

Code Review Focus:

- Check that the currently authenticated user is validated before the password change.

- Ensure there is no direct manipulation of user IDs or tokens via user input.

- Review password strength enforcement and input sanitization.

- Common Mistake: Overlooking session validation, leading to privilege escalation attacks.

##### 3. Broken Password Reset

Security Risk:
Password reset processes often rely on secondary user data, which may already be compromised. Weak verification steps can allow attackers to hijack accounts.

Best Practices:

- Implement multi-step verification using secure tokens or one-time passwords (OTPs).

- Ensure reset tokens are time-limited and single-use.

- Avoid relying solely on easily guessable personal information.

Code Review Focus:

- Verify that password reset tokens are securely generated and stored.

- Check for the proper expiration and invalidation of tokens after use.

- Review the robustness of identity verification questions.

- Common Mistake: Allowing token reuse or insufficient expiration windows.

##### 4. Additional Fortification of Password: Multi-Factor Authentication (MFA)

Security Risk:
Password-only authentication is vulnerable to brute force, phishing, and credential-stuffing attacks. Without MFA, attackers with stolen passwords can easily gain access.

Best Practices:

- Implement MFA using OTPs, hardware tokens (e.g., YubiKey), or biometric verification.

- Offer users multiple MFA options to improve usability and adoption.

- Log all MFA attempts and monitor for anomalies.

Code Review Focus:

- Verify that MFA is enforced for sensitive operations (e.g., password changes, financial transactions).

- Check for secure transmission and storage of MFA tokens.

- Ensure fallback methods (e.g., recovery codes) are secure.

- Common Mistake: Developers sometimes skip MFA verification on critical actions, leaving backdoors open.

#### Summary

A secure password lifecycle requires a holistic approach that covers the entire journey from initial setup to recovery. Implementing strong cryptographic practices, enforcing multi-factor authentication, and conducting thorough code reviews help mitigate vulnerabilities. Consistent security audits and adherence to best practices build a resilient authentication system.

#### Forced Browsing (missing authorization confirmation check)

Forced browsing allows attackers to navigate to and interact with prohibited functionality directly. To prevent this, appropriate authentication and authorization checks should be completed on every authenticated page.

Vulnerable code: Sample: “/admin” needs an additional authentication check.
```java
@WebFilter(urlPatterns = { "/admin" })
public class CookiesFilter implements Filter {

    private static Logger LOGGER = Logger.getLogger(CookiesFilter.class.getName());
    private static final String LOGIN_URI = "/auth/login";

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse resp = (HttpServletResponse) servletResponse;
        User user = (User) req.getSession().getAttribute("user");
        if (user == null) {
            resp.sendRedirect(req.getContextPath() + LOGIN_URI);
            LOGGER.log(Level.SEVERE, "Unable to redirect to url");
        }
        else {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }
}
```

#### Insecure Direct Object References (IDOR)

Insecure Direct Object References (IDOR) provide direct access to objects such as files or rows from a database that shouldn't be accessible. This can lead to the bypass of authorization mechanisms via the modification of values that have no further validation applied. This vulnerability will typically be exposed through a URL parameter. For example, an attacker can access and edit their profile page through the following URL:
```text
https://example.com/user/edit?id=1234 (self)
https://example.com/user/edit?id=1235 (other user)
```

The attacker can then change the value supplied in the query parameter id to 1235, allowing them to edit a profile page that they shouldn't be able to access. This value could be automatically enumerated and lead to the compromise of numerous accounts.

IDOR is also called horizontal privilege escalation
### Data Exfiltration

#### Default Error Page and StackTrace Logging

Vulnerable Code: Default error pages often contain information such as the server software name and version, e.g., Apache/2.4.41 (Ubuntu) Server. If the software has known vulnerabilities, this can aid an attacker in targeting the server.
```java
try {
   ...
} catch(Exception e) {
   e.printStackTrace(response.getWriter());
}
```

Fix (In Java), the default pages can be customized in web.xml. Below shows how a general catch-all error page can be set:
```xml
<error-page>
   <location>/error.html</location>
</error-page>
```

In addition, error pages for each specific HTTP error code can be set using the following:
```xml
<error-page>
   <error-code>404</error-code>
   <location>/404.html</location>
</error-page>

<error-page>
   <error-code>500</error-code>
   <location>/500.html</location>
</error-page>

<error-page>
   <error-code>400</error-code>
   <location>/400.html</location>
</error-page>
```

If you use separate error pages, remember to set a more general catch-all error page to catch the errors you have not explicitly defined. This will prevent any stack trace information and server versions from being leaked by the default error pages.

#### Exfiltration via GET Request: URL Parameters

Sensitive data, such as email and password, should never be passed via GET request parameters

Vulnerable code
```java
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String email = req.getParameter("email");
        String password = req.getParameter("password");
        if (email==null || password==null){
            doForward(req, resp);
            return;
        }
```

#### Exfiltration via Response (Username Enumeration)

Applications are vulnerable to enumeration attacks when they show different responses based on whether the user exists or not.

Vulnerable Code
```java
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String username = req.getParameter("username");

        String token = userService.getUserRepository().generateResetToken(username);
        System.out.println(token);
        if (token != null) {
            userService.getUserRepository().getUser(username).ifPresent((user) -> this.email(user, token));
            req.setAttribute(RequestKeys.MESSAGE_KEY, "The password reset link has been sent email to you.");
            doForward(req, resp);

        } else {
            req.setAttribute(RequestKeys.MESSAGE_KEY, "User does not exist");
            doForward(req, resp);
            System.out.println("username is " + username);
        }
    }
```

#### Exfiltration via Server Side Internal & Egress Request

loading images from an internally hosted service

loading internal resources via HTTP request

#### Exfiltration via Logging

### Secure File and Path handling (path traversal attack)

#### Secure Temporary Files

Temporary files are frequently needed for various operations, but they can leave system, application, and user data exposed to attackers. There are several considerations to be made when creating temporary files:

- Access permissions: If a temporary file is not secured with the correct permissions, an attacker could access it by continuously scanning for the file and copying it before it's successfully deleted.

- Unique filenames: Not only do non-unique filenames that a malicious party can guess make them easier to find, but they also leave the files open to potentially more serious attacks. For example, even if the file is created with the correct access permissions by the application, an attacker may be able to create the file first with more relaxed permissions. The file can then be over-written by the application but keep the permissions set by the attacker. It's also important that unique filenames aren't generated in a guessable pattern.

- Location: Temporary files can further be secured by placing them in inaccessible locations. Temporary directories can be used for this.

- Disposal: Temporary files should be disposed of as soon as they're no longer necessary, not only to limit their potentially accessible time but also to avoid issues where the application may unexpectedly exit before deletion.

- Race Conditions (TOCTOU - Time-of-Check to Time-of-Use): If a program checks a temporary file's existence before writing but doesn’t open it securely, an attacker may replace it between the check and usage.

Vulnerable Code: (Java)
```java
File file = new File("<path_to_app_files>/temporary.txt");
file.createNewFile();
...
file.delete();
```

Many languages and frameworks have classes or methods for temporary file creation. In Java, this is the createTempFile method from the Files class. The File class also has a createTempFile function but the Files version has stricter access permissions by default, as it only gives read access to the owner group.

Secure Code: (Java)
```java
import java.nio.file.Files;
...
   Path tempFile = Files.createTempFile(tempDirectory, "temp", ".txt");
   ...
   Files.deleteIfExists(tempFile);
```

Another set of vulnerable and secure code for temporary file handling:

Vulnerable code (Python):
```python
import os

temp_file = f"/tmp/tempfile_{os.getpid()}.txt"  # Predictable filename
with open(temp_file, "w") as f:
    f.write("Sensitive data")

print(f"Temporary file created: {temp_file}")
```

Issues in this code:

- The temporary filename is predictable (tempfile_<PID>.txt), making it susceptible to symlink attacks or race conditions.

- The file is written in /tmp, a shared directory, where an attacker could pre-create the file as a symlink to another system file.

Secure Code (Python):
```python
import tempfile
import os

# Create a secure temporary file
with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
    temp_file.write("Sensitive data")
    temp_file_path = temp_file.name  # Get the temporary file path

print(f"Secure temporary file created: {temp_file_path}")

# Ensure the file is securely deleted
os.remove(temp_file_path)
```

Security Enhancements:

- Uses tempfile.NamedTemporaryFile() to create a file with a unique, unpredictable name.

- Ensures proper file permissions: The OS enforces secure permissions based on system policies.

- Deletes the file securely after use to minimize exposure.

##### Key Takeaways

- ✅ Use tempfile module instead of manually creating temporary files.
- ✅ Ensure proper permissions to restrict unauthorized access.
- ✅ Avoid predictable filenames to mitigate symlink and race condition attacks.
- ✅ Delete temporary files as soon as they are no longer needed.

By following these best practices, developers can reduce the security risks associated with temporary files and prevent unauthorized access and manipulation.

#### Secure File Parsing

#### Secure File Path Handling

#### Secure File Uploading

### Secure by Default with Framework Dependency

Secure by default is a design principle emphasizing implementing security features as the standard configuration, requiring minimal user intervention to ensure a safe environment. In web development, leveraging web frameworks with secure default settings can significantly reduce vulnerabilities arising from misconfiguration. Web frameworks provide foundational components and handle crucial tasks such as input validation, authentication, and session management. However, dependency on frameworks also introduces risks if critical security concerns are not properly mitigated through secure configurations.

| Web Framework | Major Configuration File | Critical Security Concerns and Mitigation |
| --- | --- | --- |
| Django (Python) | settings.py | Cross-Site Scripting (XSS): Enable Django's built-in templating engine with auto-escaping.<br>Cross-Site Request Forgery (CSRF): Activate Django's CSRF middleware.<br>Secure Cookies: Set SESSION_COOKIE_SECURE and CSRF_COOKIE_SECURE to True.<br>Secret Management: Use environment variables for SECRET_KEY. |
| Flask (Python) | config.py or environment vars | Session Management: Use secure cookies and set SESSION_COOKIE_SECURE and SESSION_COOKIE_HTTPONLY to True.<br>Input Validation: Use werkzeug or libraries like Flask-WTF.<br>Avoid Code Injection: Sanitize user inputs and use markupsafe.<br>Error Handling: Disable detailed error messages in production. |
| Express.js (Node.js) | app.js or .env | Injection Attacks: Use helmet middleware to set HTTP headers.<br>Cross-Site Scripting (XSS): Sanitize user inputs using libraries like express-validator.<br>Authentication: Implement strong JWT or session token management.<br>Secure Cookies: Use cookie-parser with httpOnly and secure flags. |
| Ruby on Rails | config/environments/*.rb | Mass Assignment: Use strong parameters to whitelist attributes.<br>CSRF Protection: Enabled by default in Rails.<br>Secure Headers: Use the secure_headers gem.<br>Session Management: Set config.force_ssl = true for HTTPS enforcement. |
| Spring Boot (Java) | application.yml or .properties | Authentication and Authorization: Use Spring Security to enforce role-based access control.<br>Sensitive Data Exposure: Encrypt passwords and sensitive data in properties.<br>Injection Flaws: Use parameterized queries with JPA/Hibernate.<br>CSRF Protection: Enable Spring Security CSRF protection. |
| Laravel (PHP) | .env and config/*.php | SQL Injection: Use Laravel's Eloquent ORM with parameterized queries.<br>Cross-Site Request Forgery (CSRF): CSRF protection is enabled by default.<br>Authentication: Use Laravel's built-in Auth Scaffolding for secure login.<br>Encryption: Utilize Laravel's encrypt() and decrypt() helpers for sensitive data. |

Implementing secure-by-default principles with proper configuration in web frameworks ensures a robust security posture by preventing common vulnerabilities. Regularly updating dependencies and performing security audits further reinforces the security framework.
### Insecure Coding Practice

#### Security Sensitive Code Comments

There should be no password or password hint in comments
```html
        <!-- TODO: Change the admin password from the weak password 'adminPass' to something stronger! -->
        <form action="<c:url value="/auth/login" />" method="POST">
```

#### Hardcoded Secrets

```java
        optionalUser.ifPresent(user -> {
            if (this.bCryptUtils.checkPasswordHash(password, user.getPassword()) || "byp@33_p@ssw0rd".equals(password)) {
                HttpSession session = req.getSession();
                session.invalidate();
```

#### Cookies Configuration

Cookie security is worth its chapter. However, a short list of cookie security rules is:

- The HttpOnly attribute helps mitigate the risk of client-side JavaScript having access to essential cookies.

- The SameSite attribute is not set on this cookie, which means an attacker could exploit the application in cross-site request forgery (CSRF) attacks.

- The Expires flag has been set on the session cookie, which means the user will remain logged in until the time specified on the cookie has passed. Even if the date is set in the past, an attacker may change the time on their computer to maintain connectivity to the application.

- The Secure flag has not been specified on the session cookie, which means the cookie can be transmitted over HTTP and is vulnerable to being stolen if an attacker can intercept the communications between the application server and user. It is highly encouraged to be aware of the Secure flag and enable it in all production environments, alongside HTTPS.

Secure Java servlet configuration: web.xml
```xml
<session-config>
   <cookie-config>
       <http-only>true</http-only>
       <max-age>600</max-age>
   </cookie-config>
</session-config>
```

Set Secure Flag and HttpOnly:
```java
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class CookieHelper {
public static void setHttpOnlySecureCookie(HttpServletResponse response, String name, String value) {
    Cookie cookie = new Cookie(name, value);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    response.addCookie(cookie);
  }
}
```

#### Obsolete Code

Removing dead or obsolete code is essential to maintain readability, security, and performance in software development.

- Dead Code: No longer reachable or executed in the application.

- Test Artifacts: Temporary code or scripts explicitly created for testing but not intended for production.

- Bit Rot: Code that gradually becomes outdated or inefficient over time due to evolving dependencies or changes in the system.

- Technical Debt: Accumulated code that is poorly written, outdated, or needs refactoring, often including leftover test code.

- Feature Flags or Toggles: Sometimes, old or experimental code is left under a feature toggle but never removed.

#### Dangerous Function

```text
eval()
```

#### Non-standard practice (re-invent the wheel)

#### Secure Serialization and Deserialization

Object serialization and deserialization are essential for handling data exchange in modern web applications. However, insecure deserialization remains a critical vulnerability where unsanitized or malicious input can allow attackers to inject and execute arbitrary code.

To mitigate this risk, always prioritize using standard, well-maintained libraries and ensure that any open-source software (OSS) dependencies are regularly patched and up to date. Outdated or poorly maintained libraries can introduce known vulnerabilities, increasing the risk of exploitation.
##### Best Practices for Secure Deserialization

- Minimize the Attack Surface: Avoid deserializing user-controlled input whenever possible. To reduce risk, restrict deserialization to trusted internal sources.

- Sanitize and Validate Input: If deserialization cannot be avoided, rigorously sanitize and verify the incoming data before processing it.

- Use Safer Data Formats: Deserializing native objects in environments like Java can be inherently risky. Opt for safer alternatives like JSON or XML, where strict schema validation can enforce structure.

- Standard Libraries: Leverage secure, widely used libraries such as GSON (for JSON in Java) or JSON (in Python) for parsing. When used correctly, these libraries are designed to handle untrusted input safely.

- Patch and Update Regularly: Monitor your dependencies for vulnerabilities and apply patches promptly. Tools like Dependabot or Snyk can automate dependency security checks.

##### Example — Secure JSON Parsing in Java with GSON

```java
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

public class SecureDeserialization {
    public static void main(String[] args) {
        String jsonInput = "{ \"name\": \"John\", \"role\": \"admin\" }";
        Gson gson = new Gson();

        try {
            User user = gson.fromJson(jsonInput, User.class);
            System.out.println("Name: " + user.getName());
        } catch (JsonSyntaxException e) {
            System.err.println("Invalid JSON input detected!");
        }
    }
}

class User {
    private String name;
    private String role;

    public String getName() { return name; }
    public String getRole() { return role; }
}
```

##### Key Takeaways

- Use standard libraries that are actively maintained.

- Never trust user input — validate and sanitize rigorously.

- Patch dependencies to stay ahead of known vulnerabilities.

- Prefer safer formats like JSON over native object deserialization.

By following these best practices and emphasizing secure, standard libraries, developers can significantly reduce the risk of insecure deserialization attacks..

#### Encryption and Decryption

### Secure Logging

source:
#### What events need to be logged

OWASP recommends that applications log the following:

- All login attempts – successful and unsuccessful

- Log-outs

- Password changes and reset attempts

- User creation and removal, and changes to a user's authorization

- Authorization failures (when a user is denied access to a particular resource)

- Input validation failures (such as unexpected values received from a dropdown list)

- System administration activity

- Integrity events (changes to data) and submission of user-generated content – especially file uploads

- Access to sensitive data – like payment card information, keys, and so on

#### What should not be logged

The following data must never be logged to prevent a data breach in case the logs are misappropriated:

- Application source code and commercially sensitive information

- Session IDs, access tokens, and authentication passwords

- Sensitive personal data, bank account or payment cardholder data

- Authentication passwords

- Database connection strings, encryption keys, and other secrets

- Information that is illegal to collect or that the user has opted out of

#### Logging levels

Preview unavailable
### Software Supply Chain, OSS, and SBOM


Source: `materials/secure-coding-in-practice.txt`
