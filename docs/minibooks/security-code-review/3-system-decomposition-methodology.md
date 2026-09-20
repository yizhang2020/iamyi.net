---
title: System Decomposition Methodology
keywords:
  - security code review
  - review methodology
  - threat modeling
  - trust boundaries
  - application security
description: A practical chapter on decomposing a system into reviewable subsystems, grouping code by business purpose, and tracing data flows across trust boundaries.
---

## Chapter 3 - System Decomposition Methodology

Security review starts by making a large system understandable.

The reviewer should not begin by reading random files. A useful review starts by decomposing the system into smaller subsystems that have clear business purpose, functional responsibility, and security boundaries.

This chapter teaches that decomposition method. It combines business logic review, authentication and authorization review, and data-flow tracing into one workflow. The result is a map that tells the reviewer where code belongs, where data crosses boundaries, and where security controls must be verified.

## Start With the Complete System

System decomposition starts with the system as one object.

Before reviewing classes or functions, the reviewer should understand why the system exists. What business motivation does it serve? What project objective does it support? What user stories or operational goals make the system useful?

This creates the first review frame. The system is not only a collection of files. It is a set of business and technical goals implemented through connected functions.

The reviewer uses that frame to ask which parts of the system protect data, change state, grant access, call other services, or enforce user intent.

## Define the Internal Structure

The next step is to define the system's internal structure.

Start from business motivation, then move to project objectives, functional goals, and user stories. Each user story usually points to one or more capabilities. Those capabilities become candidate subsystems.

For example, a user account system may separate into registration, login, session management, profile management, password reset, authorization, notification, and audit logging. These subsystems are functionally separated, but they are still connected.

This internal structure gives the reviewer a first map. It shows what each subsystem is supposed to do and which goals it supports.

Once the map exists, group routes, services, classes, functions, jobs, data models, and configuration under the subsystem they support. This turns scattered code into reviewable units.

## Review Business Logic Before File Structure

Business logic helps define subsystem boundaries.

A codebase may not be organized the same way the business works. Files may be grouped by framework convention, team ownership, or historical accident. Security review should still start from what the system is trying to enforce.

The reviewer should ask what journey the user is expected to follow. What should the user be allowed to do? What order should the steps happen in? What state must exist before the next action is allowed?

These questions reveal subsystems. A password reset flow, for example, may include user lookup, token generation, email delivery, token verification, password update, session invalidation, and audit logging. Those parts may live in different files, but they belong to one reviewable security workflow.

Authentication and authorization are especially useful for decomposition. Authentication asks who the caller is. Authorization asks whether that caller can perform the action on the target object. Each place where these questions must be answered is a subsystem boundary or a sensitive control point.

## Trace Data to Separate Connected Subsystems

Data-flow tracing shows how subsystems connect.

After business logic defines the first subsystem map, the reviewer follows important data from source to sink. A source is where data enters the system. A sink is where that data becomes security-sensitive, such as a database query, authorization decision, file path, HTML response, internal request, parser, or log.

Tracing the journey of data helps separate and connect subsystems at the same time. A user ID may enter through an HTTP parameter, pass through a controller, reach a service, load a database object, and then require an ownership check. That path may cross routing, business logic, data access, and authorization subsystems.

The reviewer should not treat those layers as isolated files. The review target is the path. If attacker-controlled data crosses a trust boundary, the reviewer must know which subsystem receives it, which subsystem transforms it, and which subsystem enforces the control.

This is why data-flow tracing belongs inside system decomposition. It proves whether the proposed subsystem boundaries match how the application actually processes data.

## Model Threats for Each Subsystem

Threat modeling tests each subsystem against realistic abuse.

For each subsystem, start with intent. What is this subsystem supposed to do? What data does it receive, change, store, or expose? What authority does it have? What would go wrong if an attacker controlled its input or called its interface out of order?

Then list the attack surface. This includes interfaces, services, APIs, data exchange points, background jobs, messages, webhooks, file operations, and trust boundaries. These are the places where input, authority, or state crosses from one context into another.

Threat modeling helps the reviewer test robustness, offensiveness, and resilience. Robustness asks whether the subsystem handles hostile input and unexpected state. Offensiveness asks how an attacker could abuse the subsystem. Resilience asks whether the subsystem fails safely and leaves useful evidence.

Frameworks such as STRIDE and MITRE ATT&CK can help structure this thinking. STRIDE helps classify threat types. ATT&CK helps connect code behavior to realistic adversary techniques. The framework is not the goal. The goal is to produce concrete risks and attack paths that can be verified in code.

## Verify Controls at the Code Layer

The final step reaches classes, methods, and lines of code.

At this layer, the reviewer verifies security controls. A security control is the code or configuration that prevents, detects, limits, or records abuse. Examples include authentication checks, authorization checks, input validation, output encoding, rate limits, token expiration, secure cookie flags, allowlists, logging, and safe parser settings.

The reviewer should connect each control back to the risk it is supposed to mitigate. If the threat model says a user may try to access another user's profile, the code review must verify the ownership check. If the threat model says an attacker may send internal service requests, the code review must verify destination restrictions and allowlists.

This is where review becomes evidence-based. The reviewer can say which risk was considered, where the control exists, how the data flows, and what risk remains.

## Key Takeaway

System decomposition gives security review a map.

Start with the complete system. Break it into business and functional subsystems. Review business logic, authentication, and authorization to confirm the intended boundaries. Then trace data from source to sink to verify how those subsystems actually connect.

This method prepares the reviewer for the next part: reviewing code-level vulnerabilities and verifying security controls in implementation.

