---
title: Review Parsers and Unsafe Reconstitution
keywords:
  - XXE
  - deserialization
  - JSP include
  - parser security
description: Review XXE, dynamic inclusion, and insecure deserialization as parser-trust failures.
---

## 4.3 - Review Parsers and Unsafe Reconstitution

### Overview

Parsers and object reconstitutors turn bytes into privileged behavior. When the parser follows external entities, includes paths, or deserializes attacker graphs, we inherit that power. Review whether the parser is locked down and whether untrusted streams ever reach it.

The points below are the ideas this family chapter uses again and again.

1. Parsers and object reconstitutors turn bytes into privileged behavior.
2. Lock down external entities, includes, and unsafe deserialization before untrusted streams reach them.
3. XXE, dynamic inclusion, and insecure deserialization share parser-trust failure.
4. Ask what power the parser inherits when it follows attacker-controlled structure.
5. Verify with source, sink, missing control, impact, and a proving test.

After reading this chapter, we should be able to review parser and reconstitution paths for inherited privilege and disable unsafe features by default.

## Shared Review Model

Across every variant below, keep the same evidence habit: name the **source**, the **sink**, the **missing control**, the **impact**, and a **test** that would prove a fix.

## Variants in This Family

### XXE {: #xxe }

XML External Entity (XXE) is a server-side injection flaw in XML parsers. Documents may declare entities in a DTD that reference local files, internal services, or remote URLs. When the parser expands these entities, attacker-controlled XML can read sensitive files, perform SSRF, or cause denial of service through billion-laughs expansion.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | File uploads, SOAP/SAML, RSS/Atom feeds, SVG, Office XML, config import, Ant/build parsers |
| **Input entry** | HTTP bodies, uploaded files, webhook XML, SAML metadata, batch import jobs |
| **Parser APIs** | DOM, SAX, StAX, `XmlReader`, lxml, JAXB, Jackson XML unmarshalling |
| **Factory defaults** | `newInstance()` without secure features; partial hardening that leaves DTDs enabled |
| **Transform chains** | XSLT, XPath against untrusted docs, schema validation that loads external DTDs |
| **Secondary parsers** | SVG metadata, Android plist, Excel/Word embedded XML parts |

**Appendix detail:** [XXE code reference](appendix/code-level-reference/4-03-review-parsers-and-unsafe-reconstitution.md#xxe).

### Dynamic JSP inclusion {: #jsp-include }

Dynamic JSP inclusion is a server-side path selection flaw. The application uses attacker-controlled strings to choose which JSP, servlet, or template fragment to render. Without strict allowlisting, the attacker may include arbitrary files within the web root or traverse directories with `../` sequences.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Widget loaders, theme switches, AJAX partials, mobile layout pickers, dashboard tabs |
| **Input entry** | Query parameters, JSON fields, cookies, user preference settings |
| **Include directives** | `<jsp:include page="...">`, `<c:import url="...">`, `${param.page}` in JSP paths |
| **MVC view resolution** | `return userInput`, `ModelAndView(viewName)`, dynamic Thymeleaf fragment paths |
| **Weak controls** | Prefix-only checks, string concat `"pages/" + name + ".jsp"`, no canonicalization |
| **Cross-framework equivalents** | Flask `render_template(user_path)`, Go `template.ParseFiles(name)`, Razor partial paths |

**Appendix detail:** [Dynamic JSP inclusion code reference](appendix/code-level-reference/4-03-review-parsers-and-unsafe-reconstitution.md#jsp-include).

### Insecure deserialization {: #deserialization }

Deserialization converts stored or transmitted data back into runtime objects. When the format allows arbitrary types—or when gadget chains exist in the classpath—attackers can craft payloads that execute code during deserialization. Native object serialization in Java and pickle in Python are high-risk; even JSON can be unsafe when polymorphic type metadata is honored blindly.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Session restore, cache reload, import/export, inter-service messaging, plugin state |
| **Native serialization** | `ObjectInputStream`, `pickle.loads`, PHP `unserialize`, .NET `BinaryFormatter` |
| **Polymorphic parsers** | Jackson default typing, XStream, XMLDecoder without type allowlists |
| **Data sources** | HTTP cookies, hidden fields, Redis, Kafka, session stores, uploaded files |
| **Encrypted blobs** | Serialization wrapped in encryption without authentication or integrity checks |
| **Dependency risk** | commons-collections and similar gadget-bearing libraries on the classpath |
| **Safer alternatives missing** | JSON/protobuf into plain DTOs with schema validation not used |

**Appendix detail:** [Insecure deserialization code reference](appendix/code-level-reference/4-03-review-parsers-and-unsafe-reconstitution.md#deserialization).

## Worked Example (XXE)

We walk **XXE** in depth. Apply the same tracing steps to the other variants, adjusting sources and sinks from the tables above.

### Sample vulnerable code (Python)

```python
from lxml import etree

def parse_saml_assertion(data: bytes):
    # Attacker-controlled SAML XML from SSO callback
    # Sink: external entities may resolve — file read or SSRF
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(data, parser)
```

### Step-by-step review walkthrough

1. **Search for XML parsing entry points.** Find DOM, SAX, lxml, ElementTree, and unmarshalling APIs for SOAP or SAML.
2. **Trace the Python (or equivalent) parse path.** In the sample, `resolve_entities=True` explicitly enables entity expansion. Ask whether DTDs and network fetches are blocked; they are not.
3. **Inspect parser factory configuration.** Note defaults when no hardening appears after `newInstance()` or parser construction.
4. **Review file upload types.** SVG, DOCX/XLSX (ZIP plus XML), RSS, Atom, and SAML metadata all contain XML that may carry DTDs.
5. **Check wrapper libraries.** JAXB, Jackson XML, and SimpleXML inherit underlying parser settings—verify overrides.
6. **Identify outbound requests during parsing.** External entity URLs imply SSRF risk alongside local file disclosure.
7. **Confirm tests include XXE payloads.** `<!ENTITY x SYSTEM "file:///etc/passwd">` on every parser code path.

## Risk Impact (Family)

**Local file disclosure.** External entities can read application secrets, credentials, and system files reachable by the parser process.

**SSRF and internal scanning.** Entity URLs may fetch cloud metadata, internal admin panels, or services on private networks.

**Denial of service.** Billion-laughs and quadratic entity expansion can exhaust memory and CPU during parse.

**Credential theft at scale.** Cloud instance metadata endpoints are a common XXE target when parsers can reach link-local addresses.

## Fix Principles

Primary safer patterns for the worked example follow. For other languages and variant-specific fixes, use the [family appendix](appendix/code-level-reference/4-03-review-parsers-and-unsafe-reconstitution.md).

### Python

Use defusedxml or hardened lxml settings. Disable entity resolution and network access.

```python
from defusedxml import ElementTree as ET

def parse_saml_assertion(data: bytes):
    return ET.fromstring(data)
```

```python
from lxml import etree

def parse_saml_hardened(data: bytes):
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False,
    )
    return etree.fromstring(data, parser)
```

**Important:** Standard library `xml.etree.ElementTree` is safer than misconfigured lxml but defusedxml is the recommended drop-in for untrusted XML.

## Verify During Review

Use the checklist below as a family-level pass over the variants above. Each item should map to evidence in the change under review.

- Every XML parser sets `disallow-doctype-decl` or equivalent DTD prohibition on untrusted input.
- External general entities, parameter entities, and external DTD loading are disabled where DTDs must be supported.
- `XmlResolver` is null, `no_network=True`, or equivalent blocks outbound fetches during parse.
- XSLT and XPath processors use the same hardened reader settings as primary parsers.
- File upload filters that accept SVG, Office XML, or SAML assert XXE-safe parser configuration.
- Integration tests cover file disclosure and SSRF entity payloads for each parser code path.
- Include and view-resolution paths use allowlists or enums, not raw request parameters.
- Path normalization confirms resolved files stay within the intended templates directory.
- `../`, absolute paths, URL-encoded separators, and double-encoding are rejected.
- Partial and widget endpoints enforce authentication and authorization like full pages.
- No JSP under the web root exposes sensitive includes reachable through parameter tampering.
- Static and admin JSP files are not addressable through dynamic include parameters.
- User-controlled input is not passed to native object deserialization APIs.
- JSON, XML, and YAML parsers use strict schemas, safe loaders, and disabled polymorphic type gadgets.
- Session and cache blobs use signed and authenticated formats, or store opaque server-side keys instead of serialized objects.
- Dependencies with known deserialization CVEs are patched or removed.
- Safer data formats (JSON with DTOs) replace Java serialization and pickle in cross-trust-boundary flows.
- Error handling does not echo serialized payload details that aid exploit crafting.

## Code Reference (Appendix)

Payloads, language-specific sinks, multi-language examples, and full fix catalogs for every variant live in **[4.3 code reference — Review Parsers and Unsafe Reconstitution](appendix/code-level-reference/4-03-review-parsers-and-unsafe-reconstitution.md)**.

## Reference

- Appendix — [4.3 code reference](appendix/code-level-reference/4-03-review-parsers-and-unsafe-reconstitution.md)

- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [Python defusedxml](https://pypi.org/project/defusedxml/)
- [lxml XMLParser](https://lxml.de/apidoc/lxml.etree.html#lxml.etree.XMLParser)
- [Java DocumentBuilderFactory features](https://docs.oracle.com/en/java/javase/21/docs/api/java.xml/javax/xml/parsers/DocumentBuilderFactory.html)
- [OWASP XML External Entity Prevention — Java](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#java)
- [XmlReaderSettings.DtdProcessing](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings.dtdprocessing)
- [Go encoding/xml package](https://pkg.go.dev/encoding/xml)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [Flask render_template](https://flask.palletsprojects.com/en/stable/api/#flask.render_template)
- [Werkzeug safe_join](https://werkzeug.palletsprojects.com/en/stable/utils/#werkzeug.security.safe_join)
- [Spring MVC — View resolution](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-config/view-resolvers.html)
- [Jakarta Server Pages — jsp:include](https://jakarta.ee/specifications/pages/3.1/jdocs-tagdoc/core/include.html)
- [ASP.NET Core partial views](https://learn.microsoft.com/en-us/aspnet/core/mvc/views/partial)
- [Go embed package](https://pkg.go.dev/embed)
- [Go html/template — ParseFS](https://pkg.go.dev/html/template#ParseFS)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [JEP 290: Filter Incoming Serialization Data](https://openjdk.org/jeps/290)
- [Python pickle documentation — warning](https://docs.python.org/3/library/pickle.html)
- [PyYAML safe_load](https://pyyaml.org/wiki/PyYAMLDocumentation#loading-yaml)
- [pydantic validation](https://docs.pydantic.dev/latest/concepts/models/)
- [Gson user guide](https://google.github.io/gson/UserGuide.html)
- [System.Text.Json documentation](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/overview)
- [Go encoding/json Decoder.DisallowUnknownFields](https://pkg.go.dev/encoding/json#Decoder.DisallowUnknownFields)
