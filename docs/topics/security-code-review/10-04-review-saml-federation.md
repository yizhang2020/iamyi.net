---
title: Review SAML Federation
keywords:
  - security code review
  - saml
  - assertion signature
  - acs url
  - replay attack
  - metadata trust
description: How to review SAML federation code for assertion signature validation, ACS URL binding, replay prevention, and metadata trust.
---

## 10.4 - Review SAML Federation

SAML federation lets enterprises sign in through an Identity Provider (IdP). Review Service Provider (SP) endpoints, metadata exchange, and assertion processing code. Confirm signatures are verified with trusted keys, ACS URLs are bound, assertions are replay-protected, and metadata is authenticated before trust is granted.

## What This Topic Is

This chapter is about **implementation review**, not generic vulnerability hunting. SAML security depends on XML signature validation, strict endpoint binding, and one-time use of assertions—not on trusting decoded XML fields after parsing.

The unsafe assumption is that a POST to the Assertion Consumer Service (ACS) URL contains a legitimate IdP response because it arrived over HTTPS. Attackers can forge assertions, replay captured responses, or swap metadata if signature verification and recipient checks are skipped.

This relates to [CWE-347](https://cwe.mitre.org/data/definitions/347.html) and [CWE-294](https://cwe.mitre.org/data/definitions/294.html) (Authentication Bypass by Capture-replay).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Enterprise SSO, B2B federation, legacy Java/.NET portals, cloud app SAML connectors |
| **Signature validation** | `wantAssertionsSigned` false, signature optional, verify response but not assertion |
| **Certificate trust** | IdP cert embedded without expiry check, metadata fetched over HTTP, thumbprint string match only |
| **ACS URL / Recipient** | Missing `Recipient`/`Destination` validation, dynamic ACS from request param, wildcard ACS in metadata |
| **Replay controls** | No `InResponseTo` check, assertion ID not tracked, clock skew unbounded |
| **Conditions** | `NotOnOrAfter` ignored, `AudienceRestriction` missing or not matched to SP entity ID |
| **XML processing** | XXE-enabled parsers, external DTD allowed—see [4.08 Review XXE](4-08-review-xxe.md) |
| **Metadata exchange** | Unsigned metadata trusted, SP uploads attacker IdP metadata in self-service config |

## Sample Vulnerable Code in Python

```python
from flask import Flask, request, redirect, session
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import base64

app = Flask(__name__)

@app.route("/saml/acs", methods=["POST"])
def saml_acs():
    saml_response = request.form["SAMLResponse"]
    xml = base64.b64decode(saml_response)
    # Parser extracts NameID without verifying assertion signature
    name_id = parse_nameid_from_xml(xml)
    # Recipient, Audience, NotOnOrAfter, InResponseTo not enforced
    session["user"] = name_id
    relay = request.form.get("RelayState", "/")
    return redirect(relay)  # open redirect via unchecked RelayState

def prepare_saml_request(req):
    return {
        "http_host": req.host,
        "script_name": req.path,
        "post_data": req.form,
        "get_data": req.args,
    }

@app.route("/saml/metadata")
def sp_metadata():
    # SP accepts any IdP metadata URL supplied by tenant admin without signature check
    idp_metadata_url = request.args["metadata"]
    load_idp_from_url(idp_metadata_url)
    return "ok"
```

## Step-by-Step Review Walkthrough

1. **Map SP and IdP roles.** Locate metadata files, ACS endpoints, single logout URLs, and libraries (OneLogin python3-saml, Spring SAML, ITfoxtec, etc.).
2. **Verify assertion signatures.** Require signed assertions (or signed outer response with signed assertion). Validate with IdP certificate from trusted metadata, including expiry and key rollover.
3. **Validate ACS binding.** Confirm `Destination` and `Recipient` match the registered ACS URL exactly. Reject assertions POSTed to alternate paths or hosts.
4. **Check replay defenses.** Store used assertion IDs (`ID` attribute) for at least the assertion validity window. Validate `InResponseTo` against the outstanding AuthnRequest ID when SP-initiated.
5. **Inspect conditions.** Enforce `NotBefore`/`NotOnOrAfter` with modest clock skew. Require `AudienceRestriction` containing the SP entity ID.
6. **Review metadata trust.** Metadata should load from configured URLs or signed bundles—not arbitrary user URLs without review. Plan certificate rollover using metadata refresh.
7. **Harden XML parsing.** Disable DTDs and external entities on SAML parsers. Review RelayState allowlists to block open redirects after login.

## Risk Impact Analysis

**Authentication bypass.** Accepting unsigned or wrongly signed assertions lets attackers craft arbitrary NameIDs and attribute statements.

**Assertion replay.** Captured SAML responses reused within validity windows grant access without fresh IdP authentication.

**Wrong IdP trust.** Untrusted metadata imports route logins to attacker-controlled IdPs that mint valid-looking assertions for their keys.

**Account linking errors.** Weak NameID policy (`EmailAddress` without confirmation) may merge attacker IdP identities with victim accounts.

**XML-side attacks.** Unsafe parsers may expose server files or SSRF via XXE before signature logic runs.

## Vulnerable Examples in Other Languages

### Java

```java
@PostMapping("/saml/SSO")
public ResponseEntity<?> acs(@RequestParam String SAMLResponse) {
    byte[] decoded = Base64.getDecoder().decode(SAMLResponse);
    Element root = DocumentBuilderFactory.newInstance()
        .newDocumentBuilder()
        .parse(new ByteArrayInputStream(decoded))
        .getDocumentElement();
    // No XML signature validation
    String nameId = root.getElementsByTagName("NameID").item(0).getTextContent();
    securityContext.setUser(nameId);
    return ResponseEntity.status(302).header("Location", "/").build();
}
```

### C#

```csharp
[HttpPost("sso")]
public IActionResult Sso([FromForm] string SAMLResponse)
{
    var response = new Response(SAMLResponse);
    // Signature validation disabled in config
    var nameId = response.GetNameID();
    await SignInAsync(nameId);
    return Redirect(Request.Form["RelayState"].ToString());
}
```

### JavaScript

```javascript
// Node SP using simplified parser
app.post("/saml/consume", (req, res) => {
  const xml = Buffer.from(req.body.SAMLResponse, "base64").toString("utf8");
  const nameID = xml.match(/<NameID[^>]*>([^<]+)<\/NameID>/)[1];
  req.session.user = nameID;
  res.redirect(req.body.RelayState || "/");
});
```

### Go

```go
func acs(w http.ResponseWriter, r *http.Request) {
    samlResp := r.FormValue("SAMLResponse")
    doc, _ := xmlquery.Parse(strings.NewReader(decode(samlResp)))
    nameID := xmlquery.FindOne(doc, "//NameID").InnerText()
    // Signature, Audience, Recipient not verified
    setSession(w, nameID)
    http.Redirect(w, r, r.FormValue("RelayState"), http.StatusFound)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use `python3-saml` with strict settings and explicit security flags.

```python
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

settings = {
    "strict": True,
    "security": {
        "wantAssertionsSigned": True,
        "wantMessagesSigned": True,
        "rejectDeprecatedAlgorithm": True,
        "allowRepeatAttributeName": False,
    },
    "sp": {
        "entityId": "https://app.example.com/saml/metadata",
        "assertionConsumerService": {
            "url": "https://app.example.com/saml/acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
    },
    "idp": {
        "entityId": "https://idp.example.com/metadata",
        "singleSignOnService": {"url": "https://idp.example.com/sso", "binding": "..."},
        "x509cert": IDP_CERT_PEM,
    },
}

@app.route("/saml/acs", methods=["POST"])
def saml_acs():
    auth = OneLogin_Saml2_Auth(prepare_request(request), old_settings=settings)
    auth.process_response()
    errors = auth.get_errors()
    if errors or not auth.is_authenticated():
        abort(403)
    if not auth.validate_timestamps():
        abort(403)
    assertion_id = auth.get_last_assertion_id()
    if replay_cache.seen(assertion_id):
        abort(403)
    replay_cache.remember(assertion_id, ttl=300)
    session["user"] = auth.get_nameid()
    return redirect(safe_relay_state(request.form.get("RelayState")))
```

**Important:** Keep `strict: True`. Load IdP certificates from reviewed metadata; refresh before expiry. Allowlist RelayState targets.

### Java

Use Spring Security SAML2 Service Provider with verified relying party registration.

```java
@Bean
RelyingPartyRegistrationRepository registrations() {
    Saml2MetadataResolver resolver = new Saml2MetadataResolver(
        "https://idp.example.com/metadata/saml2");
    RelyingPartyRegistration registration = RelyingPartyRegistrations
        .fromMetadataLocation("https://idp.example.com/metadata/saml2")
        .registrationId("corp-idp")
        .entityId("https://app.example.com/saml/metadata")
        .assertionConsumerServiceLocation("https://app.example.com/login/saml2/sso/corp-idp")
        .build();
    return new InMemoryRelyingPartyRegistrationRepository(registration);
}

http.saml2Login(saml -> saml
    .loginProcessingUrl("/login/saml2/sso/{registrationId}")
    .successHandler(validatedRelayStateHandler()));
```

**Important:** Spring validates signatures and audience by default when correctly configured. Do not replace with manual DOM parsing.

### C#

Use ITfoxtec Identity SAML2 with signature validation enabled.

```csharp
var config = new Saml2Configuration
{
    Issuer = "https://app.example.com/saml/metadata",
    AllowedAudienceUris = { "https://app.example.com/saml/metadata" },
    CertificateValidationMode = X509CertificateValidationMode.ChainTrust,
    SignatureAlgorithm = Saml2SecurityAlgorithms.RsaSha256Signature,
};

config.AllowedIssuer = "https://idp.example.com/metadata";
config.SignatureValidationCertificates.Add(idpCert);

var saml2AuthnResponse = new Saml2AuthnResponse(config);
saml2AuthnResponse.ReadSamlResponse(Request, validate: true);
if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
    throw new AuthenticationException("SAML auth failed");
var claims = saml2AuthnResponse.CreateClaimsIdentity(config);
await SignInAsync(new ClaimsPrincipal(claims));
```

**Important:** Set `validate: true` on read paths. Store consumed assertion IDs in cache with TTL matching `NotOnOrAfter`.

### Go

Use `crewjam/saml` with SP struct fields and built-in validation.

```go
import "github.com/crewjam/saml"

sp := &saml.ServiceProvider{
    EntityID:    "https://app.example.com/saml/metadata",
    Key:         spKey,
    Certificate: spCert,
    IDPMetadata: idpMetadata,
    AcsURL:      mustParseURL("https://app.example.com/saml/acs"),
    MetadataURL: mustParseURL("https://app.example.com/saml/metadata"),
}

func acs(w http.ResponseWriter, r *http.Request) {
    err := r.ParseForm()
    assertion, err := sp.ParseResponse(r, []string{pendingRequestID})
    if err != nil {
        http.Error(w, "invalid SAML response", http.StatusForbidden)
        return
    }
    if replayCache.Exists(assertion.ID) {
        http.Error(w, "replay detected", http.StatusForbidden)
        return
    }
    replayCache.Add(assertion.ID, assertion.NotOnOrAfter)
    setSession(w, assertion.Subject.NameID.Value)
}
```

**Important:** `ParseResponse` validates signature, destination, and timing when IdP metadata is correct. Track SP-initiated request IDs and enforce them with `InResponseTo`.

## Verify During Review

- Assertions (or outer responses) are **XML signature validated** with current IdP keys from trusted metadata.
- **ACS URL, Destination, and Recipient** match registered SP endpoints exactly.
- **Assertion IDs** are single-use; **InResponseTo** matches outstanding AuthnRequest when applicable.
- **Audience** equals SP entity ID; **NotBefore/NotOnOrAfter** enforced with bounded clock skew.
- IdP metadata and certificates come from **trusted sources** with rollover planned before expiry.
- SAML parsers disable **XXE**; **RelayState** is allowlisted.

## Reference

- [OASIS SAML 2.0 Core](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [OASIS SAML 2.0 Bindings](http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
- [OASIS SAML 2.0 Metadata](http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OneLogin python3-saml](https://github.com/SAML-Toolkits/python3-saml)
- [Spring Security — SAML2 Service Provider](https://docs.spring.io/spring-security/reference/servlet/saml2/login/index.html)
- [ITfoxtec Identity SAML2](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2)
- [crewjam/saml](https://github.com/crewjam/saml)
