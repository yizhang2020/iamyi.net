---
title: Think Like a Security Reviewer
keywords:
  - security code review
  - secure coding principles
  - trust boundaries
  - validation
  - defensible confidence
description: Core principles that guide security review, including uncertainty reduction, trust boundaries, secure defaults, and observable behavior.
---

## Chapter 2 - Think Like a Security Reviewer

Security review is a way to reduce uncertainty.

Security code review starts with an attacker in mind. This chapter explains how that mindset becomes a repeatable practice. The reviewer is not only looking for known bug patterns. The reviewer is testing assumptions.

That is the core objective. Security review asks what the code assumes, whether that assumption is safe, and what happens when the assumption is false.

## Reduce Uncertainty

Software always contains uncertainty.

The reviewer may not know who controls an input. The developer may not know whether a downstream function trusts that input. The team may not know whether a feature can be reached in an unexpected order.

Security review reduces that uncertainty by making questions explicit:

- What is trusted?
- What is attacker-controlled?
- What security control is expected?
- Where is that control enforced?
- What happens if the control fails?

The goal is not to prove perfect safety. The goal is to reach defensible confidence. A reviewer should be able to explain what was checked, what evidence was found, and what risk remains.

## Think in Threats, Not Only Bugs

A bug is a defect in implementation. A threat is a way the system can be abused.

Security review needs both views. A reviewer may find a missing validation check, but the next question is more important: what can an attacker do with it?

For example, client-side validation can improve user experience:

```html
<input type="text" id="username" name="username" pattern="[a-zA-Z0-9]{4,20}" required>
```

This helps the browser guide normal users. It does not prove the server is safe. An attacker can bypass the browser and send a request directly.

The review principle is simple: do not trust a control just because it appears in the client. Security controls must be enforced where the attacker cannot remove them.

## Verify Assumptions

Security review should separate assumption from evidence.

An assumption sounds like this: "The user cannot change that value." Evidence sounds like this: "The server derives that value from the authenticated session and ignores the request parameter."

This difference matters. Many security issues happen when code trusts a value because the normal user interface does not expose it. Attackers are not limited to the normal interface.

A reviewer should ask:

- Where does this value come from?
- Can the user modify it?
- Is it checked on the server?
- Is the check close enough to the sensitive action?

These questions prevent a review from becoming a checklist exercise. They force the reviewer to connect implementation to trust.

## Respect Trust Boundaries

A trust boundary is a place where data moves from one level of trust to another.

Examples include browser to server, public API to internal service, user session to admin action, and uploaded file to parser. Security review pays close attention to these boundaries because assumptions often break there.

Cookies are a simple example. Cookie attributes define how much trust the browser and server place in session data:

```xml
<session-config>
   <cookie-config>
       <http-only>true</http-only>
       <max-age>600</max-age>
   </cookie-config>
</session-config>
```

`HttpOnly` helps protect cookies from client-side script access. `Secure` helps ensure cookies are sent over HTTPS. `SameSite` can reduce cross-site request risk.

The review principle is not "set every flag and move on." The principle is to understand the boundary. Session data crosses between browser and server, so the reviewer must ask how it is protected.

## Prefer Secure Defaults and Least Privilege

Secure defaults reduce the chance that a developer has to remember every security detail.

A secure default means the safer behavior happens unless someone deliberately changes it. Least privilege means code, users, and services should have only the authority they need.

These principles matter because review cannot depend on perfect memory. A framework that encodes output by default, a session cookie that is secure by default, or a role check that is required by default reduces the number of risky decisions.

Security review should look for places where the default is too permissive. It should also look for custom logic that bypasses framework protections.

## Make Behavior Observable

Security review also checks whether important behavior can be observed.

If authentication fails, authorization is denied, validation rejects input, or sensitive data is accessed, the system should leave useful evidence. Good logging helps teams investigate abuse and confirm that controls work.

But observability has limits. Logs should not expose secrets, passwords, tokens, session identifiers, or sensitive personal data. A log that helps debugging can become a data leak.

This is the review balance. The system should record enough to support investigation, but not so much that the logs become another sensitive data store.

## Key Takeaway

Security review is guided by principles, not only by bug lists.

The reviewer reduces uncertainty, thinks in threats, verifies assumptions, respects trust boundaries, prefers secure defaults, and checks whether important behavior is observable. These principles turn security review into a repeatable discipline.

The next chapter turns this discipline into a practical manual review method.

