---
title: Define Security Code Review
keywords:
  - security code review
  - secure coding
  - AppSec
  - defensible confidence
  - DevSecOps
description: A short introduction to security code review as a deeper form of code review focused on abuse, trust, and risk.
---

## Chapter 1 - Define Security Code Review

Security code review is code review with an attacker in mind.

General code review is a checkpoint for quality, maintainability, and shared understanding. Security code review keeps that foundation. It still asks whether the code is understandable and aligned with intent. Then it asks a harder question: what happens if the input, user, or environment is hostile?

This is what makes security review different. It does not only ask whether the feature works. It asks whether the feature can be abused.

## Distinguish Correct Code From Safe Code

Functional correctness and security are related, but they are not the same.

A login feature may accept a username and password. It may return the correct user when the credentials are valid. From a functional view, that can look successful.

But the implementation can still be unsafe:

```sql
sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

The code may produce a valid query. The security problem is that attacker-controlled input is mixed into the query structure. A security reviewer asks what happens when `username` or `password` contains SQL syntax.

The safer pattern separates code from data:

```java
String query = "SELECT * FROM User WHERE username = ? AND password = ?";

PreparedStatement statement = connection.prepareStatement(query);
statement.setString(1, username);
statement.setString(2, passwordHash);

resultSet = statement.executeQuery();
```

This example shows the difference. General review may ask whether the login works. Security review asks whether the login can be manipulated.

## Ask Security Questions

Security review starts with a different set of questions.

A reviewer should ask:

- What input is attacker-controlled?
- What trust boundary is crossed?
- What authority does the code have?
- What validation or encoding is applied?
- What impact is possible if the assumption is wrong?

These questions move the review from behavior to abuse. They help the reviewer see beyond the normal path.

This matters because attackers do not use software only as intended. They change parameters, skip screens, replay requests, inject syntax, and look for places where the code trusts the wrong thing.

## Map Risk to Confidentiality, Integrity, and Availability

Security code review often maps risk to three basic objectives: confidentiality, integrity, and availability.

Confidentiality asks whether the code protects data from unauthorized access. An insecure direct object reference can break confidentiality if one user can view another user's record by changing an ID.

Integrity asks whether the code prevents unauthorized changes. A missing authorization check can break integrity if a user can modify data they do not own.

Availability asks whether the code keeps the system usable. Unsafe parsing, expensive operations, or unbounded resource use can create denial-of-service risk.

These objectives keep the review practical. The reviewer does not need to label every issue perfectly at first. They need to explain what can go wrong and why it matters.

## Treat Working Output as Review Evidence, Not Proof

XSS is another example of correct behavior becoming unsafe behavior.

A page may retrieve a username and display it:

```html
<div id="hello-message">
    <p>Hello user <%=request.getAttribute("user")%>. Welcome to the platform!</p>
</div>
```

The page may look correct during normal testing. But if the username contains markup or script content, the page may render attacker-controlled code.

The safer pattern uses output encoding:

```jsp
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<div id="hello-message">
    <p>Hello user <c:out value="${requestScope.user}" />. Welcome to the platform!</p>
</div>
```

The security issue is not that the page displays the wrong value. The issue is that it displays the value in the wrong trust context.

## Reduce Risk Instead of Only Finding Bugs

Security code review is not only a hunt for individual bugs.

A single finding is useful, but the larger goal is risk reduction. The reviewer looks for insecure assumptions, missing controls, and patterns that may repeat across the codebase.

This is where "defensible confidence" matters. A security reviewer should be able to explain what was reviewed, what evidence was found, what assumptions were tested, and what risk remains.

That does not mean every line has been proven safe. It means the review produced a reasoned security judgment.

## Fit Security Review Into Delivery

Security review works best when it is part of the development lifecycle.

It can happen during design, when trust boundaries are still flexible. It can happen during implementation, when pull requests are still small. It can happen in CI/CD, where automated checks can support human review.

In a DevSecOps workflow, security review should not be a late surprise. It should be part of how teams build software. Automation can help find common patterns, but human review is still needed for context, ownership, and abuse paths.

## Key Takeaway

Security code review is a deeper form of code review.

It starts with the same engineering discipline: read the code, understand the intent, and question the assumptions. Then it adds the security lens: who can influence this behavior, what trust boundary is crossed, and what impact is possible?

The next chapter builds on this by explaining how a security reviewer thinks through trust, attacker control, and uncertainty.

## Source References

- `materials/book-security-code-review/book-outline.md`
- `materials/book-security-code-review/book-outline-code-examples.md`
- `docs/topics/security-code-review/secure-coding-in-practice.md`
