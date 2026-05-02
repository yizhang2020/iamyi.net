---
title: "Threat Modeling Case Study: Car Firmware Update via USB Stick"
date: 2026-05-02
keywords:
  - threat modeling
  - automotive
  - firmware
  - USB
description: Interview-style case study on car firmware updates over USB—structured threats and mitigations beyond "sign and encrypt."
---

# Threat Modeling Case Study: Car Firmware Update via USB Stick

## Preface

This case study comes from a real interview question (Sr. Security Engineer Position):

> *“A car firmware update is performed via a USB stick. What are the security concerns, and how would you mitigate them?”*

My initial answer was straightforward:

* The firmware image should be **signed and encrypted**
* The system must verify **integrity and authenticity during installation**
* The **CA certificate and public key** should be pre-stored on the device

Technically correct—but incomplete.

What was missing wasn’t knowledge, but **structure**. Over time, I’ve learned that security work is less about knowing isolated answers and more about **thinking systematically**.


## Start With the System

Before diving into threats, break the system into its core components:

* Firmware image (on USB stick)
* Vehicle system (target)
* USB interface (bridge between them)

Each carries different risks and responsibilities. That separation is the foundation of the analysis.


## Diagram: System & Trust Flow

```
        [ Firmware Signing Authority ]
                    |
                    | (signs firmware)
                    v
        [ Firmware Image (Encrypted + Signed) ]
                    |
                    | (copied to)
                    v
              [ USB Stick ]
                    |
                    | (physical insertion)
                    v
        [ Car USB Interface / Update Service ]
                    |
        ---------------------------------------
        |           Verification Layer        |
        |  - Signature validation             |
        |  - Certificate chain check          |
        |  - Time / CRL validation            |
        ---------------------------------------
                    |
                    | (if trusted)
                    v
           [ Firmware Installation Process ]
                    |
        ---------------------------------------
        |           Runtime Protections       |
        |  - Secure Boot                      |
        |  - Rollback protection              |
        |  - Integrity checks                 |
        ---------------------------------------
                    |
                    v
             [ Running Vehicle System ]
```

This diagram highlights something important:
**trust is not a single step—it’s enforced at multiple layers.**


## Define What Actually Matters

Security is about **risk, not completeness**.

The highest-risk scenario is installing a **malicious or tampered firmware image**, potentially affecting vehicle behavior and safety.

Lower-risk scenarios include:

* Failed updates (recoverable)
* Firmware leakage (less critical if properly protected)

This leads to three priorities:

* Protect firmware **integrity and authenticity**
* Ensure **strong verification before installation**
* Handle failure safely


## Apply Security Principles Early

Before getting into specific threats, anchor the design:

* Always fall back to a **known good state**
* Limit when and how updates can occur
* Separate critical system updates from less sensitive operations
* Use **layered defenses**, not a single control

These principles shape the system before any mitigation is applied.


## Threat Model 1: Protect the Firmware Image

The firmware on the USB stick is the first point of risk.

To ensure integrity, it must be **digitally signed**. This guarantees that any modification can be detected and that only trusted sources are accepted.

However, the trust chain itself can be attacked:

* Compromised or outdated CA certificates
* Expired certificates reused via time manipulation
* Revocation checks bypassed
* Weak hash algorithms

Mitigation requires maintaining a **strong and up-to-date trust infrastructure**.

Confidentiality adds another layer. If the firmware contains sensitive logic, it should be encrypted.

That introduces additional risks:

* Key exposure
* Weak encryption schemes

In practice, this means using secure key storage (e.g., TPM) and modern encryption standards.


## Threat Model 2: Verify During Installation

Protection at rest is not enough. The system must verify the firmware **at the moment it is installed**.

Before installation:

* Validate the signature against a trusted root
* Verify the certificate chain
* Ensure the image has not been altered

During and after installation:

* Prevent rollback to vulnerable versions
* Ensure the process is **atomic**
* Maintain a recovery path if anything fails

This is where trust becomes enforcement.


## The Role of the Interface

USB introduces a **physical attack surface**.

Unlike remote updates, this assumes local access. The primary concern is disruption rather than remote compromise.

Potential issues include:

* Interrupting the update process
* Triggering repeated failures (local DoS)

Mitigations focus on control and resilience:

* Restrict when updates are allowed
* Require user authorization
* Ensure robust failure handling


## Closing Thoughts

The most important takeaway from this exercise isn’t a specific control—it’s the approach.

A strong security analysis:

* Starts with system understanding
* Focuses on what actually matters
* Applies principles before solutions
* Builds layered defenses

Firmware security isn’t solved in one place. It’s enforced across **storage, transfer, verification, and execution**.

And that structure is what turns a partial answer into a complete one.
