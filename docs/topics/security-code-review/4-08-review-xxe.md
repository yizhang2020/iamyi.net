---
title: Review XXE
keywords:
  - security code review
  - xxe
  - xml external entity
  - xml parsing
  - dtd
description: How to read code for XML External Entity flaws—trace attacker-controlled XML to parser settings and verify external entity resolution is disabled.
---

## 4.8 - Review XXE

XXE appears when XML parsers process attacker-controlled documents with external entities, DTDs, or XInclude enabled. Start from file upload handlers, SOAP endpoints, SAML assertions, and config import features. Trace each XML input to parser factory settings.

## What This Vulnerability Is

XML External Entity (XXE) is a server-side injection flaw in XML parsers. Documents may declare entities in a DTD that reference local files, internal services, or remote URLs. When the parser expands these entities, attacker-controlled XML can read sensitive files, perform SSRF, or cause denial of service through billion-laughs expansion.

The unsafe assumption is that XML input is benign structured data. Default parser configurations often enable entity expansion. This maps to [CWE-611](https://cwe.mitre.org/data/definitions/611.html) (Improper Restriction of XML External Entity Reference).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | File uploads, SOAP/SAML, RSS/Atom feeds, SVG, Office XML, config import, Ant/build parsers |
| **Input entry** | HTTP bodies, uploaded files, webhook XML, SAML metadata, batch import jobs |
| **Parser APIs** | DOM, SAX, StAX, `XmlReader`, lxml, JAXB, Jackson XML unmarshalling |
| **Factory defaults** | `newInstance()` without secure features; partial hardening that leaves DTDs enabled |
| **Transform chains** | XSLT, XPath against untrusted docs, schema validation that loads external DTDs |
| **Secondary parsers** | SVG metadata, Android plist, Excel/Word embedded XML parts |

## Sample Vulnerable Code in Python

```python
from lxml import etree

def parse_upload(data: bytes):
    # Attacker-controlled XML body from file upload
    # Sink: external entities may resolve — file read or SSRF
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(data, parser)
```

## Step-by-Step Review Walkthrough

1. **Search for XML parsing entry points.** Find DOM, SAX, lxml, ElementTree, and unmarshalling APIs for SOAP or SAML.
2. **Trace the Python (or equivalent) parse path.** In the sample, `resolve_entities=True` explicitly enables entity expansion. Ask whether DTDs and network fetches are blocked; they are not.
3. **Inspect parser factory configuration.** Note defaults when no hardening appears after `newInstance()` or parser construction.
4. **Review file upload types.** SVG, DOCX/XLSX (ZIP plus XML), RSS, Atom, and SAML metadata all contain XML that may carry DTDs.
5. **Check wrapper libraries.** JAXB, Jackson XML, and SimpleXML inherit underlying parser settings—verify overrides.
6. **Identify outbound requests during parsing.** External entity URLs imply SSRF risk alongside local file disclosure.
7. **Confirm tests include XXE payloads.** `<!ENTITY x SYSTEM "file:///etc/passwd">` on every parser code path.

## Risk Impact Analysis

**Local file disclosure.** External entities can read application secrets, credentials, and system files reachable by the parser process.

**SSRF and internal scanning.** Entity URLs may fetch cloud metadata, internal admin panels, or services on private networks.

**Denial of service.** Billion-laughs and quadratic entity expansion can exhaust memory and CPU during parse.

**Credential theft at scale.** Cloud instance metadata endpoints are a common XXE target when parsers can reach link-local addresses.

## Vulnerable Examples in Other Languages

### Java

```java
public Document parse(InputStream in) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    // defaults: external entities may be enabled depending on JDK/parser
    DocumentBuilder builder = dbf.newDocumentBuilder();
    return builder.parse(in);
}

public void transform(InputStream xml, InputStream xsl) throws Exception {
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer t = tf.newTransformer(new StreamSource(xsl));
    t.transform(new StreamSource(xml), new StreamResult(System.out));
}
```

### C#

```csharp
public XmlDocument LoadXml(string xml)
{
    var doc = new XmlDocument();
    doc.XmlResolver = new XmlUrlResolver(); // resolves external entities
    doc.LoadXml(xml);
    return doc;
}

public XDocument ParseFeed(Stream stream)
{
    return XDocument.Load(stream); // default settings may fetch external DTDs
}
```

### Go

```go
func parseWithLib(body []byte) error {
    // Third-party XML libs may expand entities if misconfigured
    doc, err := libxml.Parse(body, libxml.DefaultParserOptions)
    return err
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use defusedxml or hardened lxml settings. Disable entity resolution and network access.

```python
from defusedxml import ElementTree as ET

def parse_upload(data: bytes):
    return ET.fromstring(data)
```

```python
from lxml import etree

def parse_upload_hardened(data: bytes):
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        dtd_validation=False,
        load_dtd=False,
    )
    return etree.fromstring(data, parser)
```

**Important:** Standard library `xml.etree.ElementTree` is safer than misconfigured lxml but defusedxml is the recommended drop-in for untrusted XML.

### Java

Disable DTDs and external entities on `DocumentBuilderFactory`.

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder builder = dbf.newDocumentBuilder();
return builder.parse(in);
```

**Important:** Partial hardening that disables only external entities while DTDs remain allowed is insufficient when DTDs are not required. Prefer `disallow-doctype-decl`.

### C#

Use `XmlReaderSettings` with DTD processing prohibited.

```csharp
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
using var reader = XmlReader.Create(stream, settings);
var doc = XDocument.Load(reader);
```

```csharp
// Legacy XmlDocument — avoid on untrusted input; if required:
var doc = new XmlDocument { XmlResolver = null };
using var reader = XmlReader.Create(stream, settings);
doc.Load(reader);
```

**Important:** Do not call `XDocument.Load(string)` or `XDocument.Load(stream)` on untrusted input without secure `XmlReader` settings.

### Go

Default `encoding/xml` does not resolve external entities. Audit third-party CGo bindings.

```go
import "encoding/xml"

func parseRequest(body []byte) (Envelope, error) {
    var env Envelope
    if bytes.Contains(body, []byte("<!DOCTYPE")) ||
       bytes.Contains(body, []byte("<!ENTITY")) {
        return env, errors.New("DOCTYPE/ENTITY not allowed")
    }
    err := xml.Unmarshal(body, &env)
    return env, err
}
```

**Important:** Reject documents containing `<!DOCTYPE` or `<!ENTITY` before third-party parsing when policy requires zero DTD support.

## Verify During Review

- Every XML parser sets `disallow-doctype-decl` or equivalent DTD prohibition on untrusted input.
- External general entities, parameter entities, and external DTD loading are disabled where DTDs must be supported.
- `XmlResolver` is null, `no_network=True`, or equivalent blocks outbound fetches during parse.
- XSLT and XPath processors use the same hardened reader settings as primary parsers.
- File upload filters that accept SVG, Office XML, or SAML assert XXE-safe parser configuration.
- Integration tests cover file disclosure and SSRF entity payloads for each parser code path.

## Reference

- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [Python defusedxml](https://pypi.org/project/defusedxml/)
- [lxml XMLParser](https://lxml.de/apidoc/lxml.etree.html#lxml.etree.XMLParser)
- [Java DocumentBuilderFactory features](https://docs.oracle.com/en/java/javase/21/docs/api/java.xml/javax/xml/parsers/DocumentBuilderFactory.html)
- [OWASP XML External Entity Prevention — Java](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#java)
- [XmlReaderSettings.DtdProcessing](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings.dtdprocessing)
- [Go encoding/xml package](https://pkg.go.dev/encoding/xml)
