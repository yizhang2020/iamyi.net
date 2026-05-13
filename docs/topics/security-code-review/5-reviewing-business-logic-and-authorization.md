---
title: Review Business Logic and Authorization
keywords:
  - security code review
  - business logic
  - authorization
  - authentication
  - IDOR
description: How to review workflows, state transitions, authentication, and authorization assumptions that basic scanners often miss.
---

## Chapter 5 - Review Business Logic and Authorization

Business logic bugs are workflow bugs.

Business logic review applies manual review thinking to the way an application is supposed to work. The issue is often not a single dangerous API. The issue is that the workflow trusts the wrong user, state, or step.

This is why business logic review needs context. The reviewer must understand what the feature is trying to enforce before deciding whether the code enforces it.

## Review the Intended User Journey

Business logic review starts with the intended journey.

What should the user be allowed to do? What order should the steps happen in? What state must exist before the next action is allowed? What should happen if a user skips a step?

These questions matter because attackers do not follow the intended journey. They change IDs, replay requests, skip screens, submit stale tokens, and call endpoints directly.

The reviewer should compare the intended journey with the actual server-side enforcement. A button hidden in the user interface is not a security control. A disabled field is not a security control. The server must enforce the rule.

## Check Authorization at Every Sensitive Step

Authentication and authorization answer different questions.

Authentication asks, "Who are you?" Every method or endpoint that performs meaningful work should verify the caller's identity or session state.

Authorization asks, "Are you allowed to do this?" Every sensitive data operation should verify ownership, role, or permission.

Authentication alone is not enough. A user can be logged in and still not be allowed to access another user's data or admin functionality.

Forced browsing shows this problem. The `/admin` path may check whether a user exists in the session:

```java
User user = (User) req.getSession().getAttribute("user");
if (user == null) {
    resp.sendRedirect(req.getContextPath() + LOGIN_URI);
}
else {
    filterChain.doFilter(servletRequest, servletResponse);
}
```

This verifies authentication. It does not prove the user is authorized as an admin. The review question is not only "Is the user logged in?" It is also "Is this user allowed to perform this action?"

## Watch State Transitions and Reset Flows

Business logic often depends on state.

Password reset is a good example. The system should know which user requested the reset, whether the reset token is valid, whether it has expired, and whether it has already been used.

The reference material highlights several review checks:

- Verify that password reset tokens are securely generated and stored.
- Check that tokens expire and are invalidated after use.
- Avoid relying only on easily guessed personal information.

These are not only implementation details. They define the workflow. If the state transition is weak, an attacker may move from "not authenticated" to "account owner" without proving ownership.

The same idea applies to password change. A logged-in user should usually verify the current password before changing it. Otherwise, a stolen session may be enough to take over the account.

## Treat CSRF and IDOR as Logic Failures

CSRF and IDOR are often business logic failures.

CSRF abuses a state-changing action that trusts the browser too much. The user may be authenticated, but the action may not represent the user's intent. Sensitive operations need CSRF protection, reauthentication, or stronger confirmation.

IDOR abuses missing ownership checks. The user may be authenticated, but the object may not belong to them:

```text
https://example.com/user/edit?id=1234 (self)
https://example.com/user/edit?id=1235 (other user)
```

The code may correctly load the object for `id=1235`. That is not enough. The server must verify that the authenticated user is allowed to access or modify that object.

This is why business logic review focuses on permission models. It asks whether each sensitive operation checks the right user, the right object, and the right action.

## Use Human Judgment Where Scanners Miss Context

Basic scanners often miss business logic flaws.

They can detect some dangerous patterns, but they usually do not understand the intended workflow. They may not know that `/admin` requires an admin role. They may not know that a password reset token should be single-use. They may not know that `id=1235` belongs to another user.

This is where human review matters. The reviewer connects code to intent, state, and ownership.

AI-assisted review can help summarize flows and generate questions. But the reviewer still needs to validate whether the workflow matches the business rule.

## Key Takeaway

Business logic review asks whether the workflow can be abused.

The reviewer checks authentication at meaningful entry points and authorization for sensitive data operations. They inspect state transitions, ownership checks, and user intent. The goal is to catch failures that look correct one function at a time, but become dangerous across the workflow.

The next chapter moves from workflow-level review into detailed code-level security analysis.

## Source References

- `materials/book-security-code-review/book-outline.md`
- `materials/book-security-code-review/book-outline-code-examples.md`
- `docs/topics/security-code-review/secure-coding-in-practice.md`
