---
title: Trace Data From Source to Sink
keywords:
  - security code review
  - review methodology
  - threat modeling
  - risk-based review
  - secure coding
description: A practical method for decomposing large systems into reviewable security scopes.
---

## Chapter 4 - Trace Data From Source to Sink

Security review needs structure.

Manual review becomes difficult when the system is too large to inspect randomly. A reviewer needs a method that turns a large codebase into smaller review targets.

The goal is not to read every file with equal attention. The goal is to find the places where security assumptions are made, enforced, or broken.

## Start With the System, Not the Line

A systematic review starts at the system level.

Before looking at a method or function, the reviewer should understand what the system does. What assets does it protect? Who uses it? What external systems does it call? What actions can change data, expose data, or grant access?

This prevents the review from becoming random file reading. A reviewer who starts with isolated code may find small bugs but miss the larger abuse path.

System-level understanding gives the reviewer a map. The map does not need to be perfect. It only needs to be good enough to guide the first review decisions.

## Decompose the Review Scope

Large systems become reviewable when they are decomposed.

A practical decomposition can move through these layers:

1. System
2. Subsystem
3. Critical component
4. Business logic
5. Class or module
6. Method or function
7. Code-level implementation

This is a narrowing process. The reviewer starts broad, then follows risk toward specific code.

For example, a user account system may contain authentication, authorization, profile management, password reset, and session handling. Each subsystem has different security questions. Password reset may require token generation review. Profile editing may require ownership checks. Session handling may require cookie and timeout review.

## Follow Critical Assets

The next step is to identify critical assets.

An asset can be data, authority, workflow state, service access, or user identity. The reviewer should ask what would matter if it were exposed, modified, or abused.

For example, an internal API proxy may look like a helper feature. But if it sends server-side requests based on user input, it becomes a high-risk review target:

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

The method is small, but the review scope is larger. The reviewer must ask what internal resources are reachable, who controls `endpoint`, and whether an allowlist limits the request.

## Map Risk to Review Depth

Not every file deserves the same review depth.

Risk should guide attention. Code that handles money, authentication, authorization, secrets, file access, internal network calls, or sensitive data deserves deeper review. Low-risk display code may need less depth.

This is how review becomes scalable. The reviewer does not ignore low-risk areas. They simply spend more time where the impact is higher and the assumptions are more dangerous.

Path traversal is a good example. A file download feature may look ordinary, but it handles a boundary between user input and the file system:

```python
file = request.args.get('filename')  # User-provided input
open(f"/var/www/uploads/{file}", "r")  # Potentially vulnerable
```

The code-level question is simple: can the user control the path? The system-level question is bigger: what files could the application read if this check fails?

## Move From Architecture to Code

A systematic review moves from architecture to implementation.

The reviewer may start with a diagram, route list, API contract, or feature description. Then the reviewer follows the sensitive flow into code. This creates a chain of evidence.

For an IDOR issue, the flow may start with a profile edit feature. The reviewer then checks the route, the request parameter, the database query, and the ownership check.

```text
https://example.com/user/edit?id=1234 (self)
https://example.com/user/edit?id=1235 (other user)
```

The important question is not only whether the URL works. The question is whether the server verifies that the authenticated user owns the object before allowing access.

## Use Bounded Analysis

Bounded analysis means the reviewer defines what is in scope.

Without a boundary, review becomes endless. With a boundary, the reviewer can produce defensible confidence. The reviewer can say what was reviewed, why it was selected, and what risk remains outside the scope.

A useful boundary may be a feature, subsystem, data flow, role, or vulnerability class. For example, a review may focus on password reset, file download, internal request handling, or admin authorization.

The boundary should be explicit. It helps the reviewer stay focused and helps the team understand what the review conclusion means.

## Key Takeaway

A systematic review starts broad and narrows with purpose.

The reviewer maps the system, identifies critical assets, decomposes the scope, and follows risk into code. This turns large systems into reviewable parts. It also makes the review easier to explain.

The next chapter applies this method to business logic and authorization, where the most important risk is often hidden in workflow behavior.

