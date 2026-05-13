---
title: Review Code Manually
keywords:
  - security code review
  - manual review
  - taint analysis
  - pull request review
  - application security
description: A practical chapter on using human judgment to review code paths, trust boundaries, authorization, exploitability, and security evidence.
---

## Chapter 3 - Review Code Manually

Manual security code review is targeted reasoning.

It is not the act of reading every line of code from top to bottom. That approach does not scale, and it often misses the real issue. A useful manual review starts with risk, follows the code that matters, and asks whether the implementation matches the security intent.

The earlier chapters defined the reviewer mindset. This chapter turns that mindset into manual review practice. Manual review is strongest when the reviewer must understand intent, ownership, trust boundaries, business behavior, and exploitability.

## Use Manual Review Where Judgment Matters

Automated tools are good at finding repeated patterns. They can detect many injection risks, hardcoded secrets, unsafe APIs, vulnerable dependencies, and missing configuration flags.

But many security flaws are not only pattern problems. They are meaning problems.

An endpoint may check that a user is logged in, but not check whether that user owns the data. A password reset flow may work correctly, but leak whether an account exists. An internal request helper may look safe in isolation, but become SSRF when a route lets users choose the path. A file download function may normalize paths, but still expose files that the user should not access.

Manual review matters because the reviewer can connect code behavior to security intent.

## Read With Attacker Questions

A manual reviewer reads code with attacker questions in mind.

The most useful questions are simple:

1. What can the attacker control?
2. What sensitive action happens here?
3. What trust boundary is crossed?
4. What must be true for this code to be safe?
5. Where is that condition verified?

These questions keep the review grounded. The reviewer is not trying to find every possible weakness at once. The reviewer is testing whether the code's assumptions are actually enforced.

Authentication and authorization show the difference. Authentication answers who the user is. Authorization answers whether that user can perform the action or access the data. A code path that checks only login status may still be vulnerable if it does not check ownership, role, tenant, or permission.

## Start From Meaningful Entry Points

Manual review should begin from meaningful entry points and sensitive operations. These are the places where attacker-controlled input, user authority, and important system behavior often meet.

Start with entry points such as routes, controllers, state-changing endpoints, and authentication flows. Then move to sensitive operations such as authorization checks, file handling, outbound requests, SQL queries, template rendering, command execution, logging, and error handling.

From there, the reviewer traces behavior. Random browsing is inefficient. A better approach is to pick a security question and follow the code until the question is answered.

For example:

> Can one user access another user's profile?

That question leads to the route, the request parameter, the current session, the database lookup, and the ownership check. If the ownership check is missing, the finding becomes clear.

## Trace Untrusted Data

Manual taint analysis means following untrusted data through the code.

The reviewer starts with a source. Common sources include request parameters, headers, cookies, JSON fields, uploaded files, environment-controlled values, and messages from other services.

Then the reviewer follows the value to a sink. Common sinks include SQL queries, HTML output, file paths, command execution, template engines, XML parsers, deserialization, outbound HTTP requests, logs, and authorization decisions.

Consider IDOR. The attacker changes a URL parameter:

```text
https://example.com/user/edit?id=1234
https://example.com/user/edit?id=1235
```

The question is not only whether `id` is a number. The question is whether the authenticated user owns `1235` or has permission to edit it. If the code loads the object by ID and updates it without an ownership check, authentication did not protect the data.

SSRF follows the same method:

```java
URL url = new URL("http://127.0.0.1" + endpoint);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
```

The reviewer should trace where `endpoint` comes from. If it comes from user input, the server may be used to reach internal routes such as `/secret`. The manual value is understanding whether that route is reachable, what the server can access, and whether the allowlist is real.

File handling also needs taint analysis:

```python
file = request.args.get('filename')
open(f"/var/www/uploads/{file}", "r")
```

The reviewer follows the filename into the filesystem call and asks whether normalization, base-directory enforcement, and authorization are all present.

## Review Pull Requests for Security Impact

Security review in a pull request should start with intent.

The reviewer should first understand what changed and why. Then the reviewer should look for changed trust boundaries. Did the PR add a new endpoint? Accept a new input field? Change an authorization check? Add a file upload? Introduce a new dependency? Start logging new data? Call an internal service?

Once the sensitive change is found, the reviewer should ask evidence-based questions:

- Where is authentication verified?
- Where is authorization verified?
- What input validation happens on the server?
- Is output encoded in the correct context?
- What abuse case tests were added?
- What happens when the caller is authenticated but not the owner?
- What sensitive data could appear in logs or responses?

Good review comments are specific. Avoid comments such as:

> This looks insecure.

Prefer:

> This route loads the account by `accountId`, but I do not see an ownership or role check before the update. Please verify the current user can modify this account and add a test where another authenticated user tries the same request.

That comment explains the source, the missing control, the impact, and the expected evidence.

## Check Password Reset and Logging

Password reset flows are good manual review targets because they combine identity, tokens, email, timing, and user-facing messages.

A reset flow may leak account existence if it returns different messages:

```java
if (token != null) {
    req.setAttribute(RequestKeys.MESSAGE_KEY, "The password reset link has been sent email to you.");
} else {
    req.setAttribute(RequestKeys.MESSAGE_KEY, "User does not exist");
}
```

The reviewer should ask whether the external response is the same for both cases, whether tokens are random and single-use, whether they expire, and whether token values are logged.

Logging has the same pattern. Logs should help investigate security events, but they should not expose secrets. A reviewer should check whether passwords, reset tokens, session IDs, access tokens, API keys, or sensitive personal data are written to logs.

Useful logs answer what happened, when it happened, who initiated it, and whether the action succeeded. Dangerous logs store the data an attacker wants.

## Write Evidence-Based Findings

A manual review finding should be written so another engineer can verify it.

A strong finding includes:

1. The source of attacker-controlled input
2. The sensitive sink or operation
3. The missing or weak control
4. The security impact
5. A short proof or reasoning path
6. The recommended fix
7. The test that should be added

This format avoids vague review feedback. It also helps distinguish real vulnerabilities from style preferences.

For example, an IDOR finding should not only say "missing authorization." It should say which parameter selects the object, which user is authenticated, which object belongs to another user, which update or read is allowed, and where the ownership check should happen.

## Avoid Common Reviewer Mistakes

Manual reviewers can miss issues too.

Common mistakes include:

- Following a checklist without understanding the flow
- Treating authentication as authorization
- Trusting client-side validation
- Assuming framework defaults are enabled
- Ignoring error messages and logs
- Reviewing only changed lines instead of affected paths
- Accepting a fix without an abuse-case test
- Reporting findings without exploitability context

The most serious mistake is losing the security question. Manual review works when the reviewer keeps asking what the attacker can control and what the application trusts.

## Key Takeaway

Manual security code review is not a replacement for automation. It is a different kind of control.

Automation finds repeatable patterns. Manual review examines meaning. It connects code to intent, trust, ownership, and exploitability.

Use manual review where human judgment gives the most value: sensitive workflows, authorization boundaries, data flows, business rules, and exceptions that tools cannot decide.

