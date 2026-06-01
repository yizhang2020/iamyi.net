---
title: Review Insecure File Parsing
keywords:
  - security code review
  - file parsing
  - zip slip
  - xml external entity
  - unsafe deserialization
description: How to read code for insecure parsing of uploaded or imported files where malformed content triggers code execution or data exposure.
---

## 4.27 - Review Insecure File Parsing

File parsers turn bytes into objects, images, archives, or documents. Review importers that accept user uploads, email attachments, and integration feeds. Trace parser configuration, entity expansion, nested archives, and whether the code trusts structure metadata from untrusted files.

## What This Vulnerability Is

Insecure file parsing treats attacker-supplied files as trustworthy input to complex format libraries. ZIP bombs, XML external entities (XXE), malicious Office macros, pickle payloads, and malformed images can exhaust memory, read local files, or execute code inside the parser or downstream handlers.

The unsafe assumption is that validating the file extension is enough. Magic bytes can be spoofed, and the real risk is often how the parser is configured and what features are enabled. This spans [CWE-502](https://cwe.mitre.org/data/definitions/502.html) (Deserialization), [CWE-611](https://cwe.mitre.org/data/definitions/611.html) (XXE), [CWE-400](https://cwe.mitre.org/data/definitions/400.html) (Uncontrolled Resource Consumption), and archive path traversal (Zip Slip).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Config import, archive upload, XML/YAML ingestion, image conversion, document preview |
| **Parser types** | ZIP, TAR, XML, YAML, pickle, Java serialization, PDF, image decoders |
| **Unsafe loaders** | `yaml.load`, `pickle.load`, `ObjectInputStream`, `BinaryFormatter` |
| **Archive sinks** | `ZipEntry.getName()` joined to output path without canonical check |
| **Resource limits** | Missing caps on entry count, uncompressed size, recursion depth |
| **Post-parse use** | Parsed objects fed into reflection, scripting, or dynamic SQL |

## Attack Payloads

Use these in authorized tests with crafted files in upload and import features. Confirm parser limits and safe loader settings per format.

### Pattern 1: Zip Slip path traversal (archive abuse scenario)

```text
# Malicious entry name inside archive
../../../../etc/passwd
..\..\windows\system32\config\sam
```

### Pattern 2: XML external entity (XXE)

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### Pattern 3: Billion laughs / entity expansion

```xml
<!ENTITY a "aaaa...">
<!ENTITY b "&a;&a;...">
```

### Pattern 4: Unsafe deserialization in file body

```python
# pickle magic bytes in uploaded .dat
cos\nsystem\n(S'whoami'\ntR.
```

### Pattern 5: YAML unsafe load

```yaml
!!python/object/apply:os.system ['id']
```

### Pattern 6: Zip bomb and nested archives

```text
42.zip containing 42.zip × N with huge uncompressed size
```

## Language-Specific Sinks and Dangerous APIs

Search for parsers that enable dangerous features on untrusted input.

### Python

```python
zipfile.ZipFile(path).extractall(dest)  # no path check
yaml.load(data)  # use yaml.safe_load
pickle.load(f)
xml.etree.ElementTree.parse(path)  # XXE risk in some configs
lxml.etree.parse(path)
```

`tarfile.extractall`, `PIL.Image.open` without size limits, `pdfplumber` on hostile PDFs.

### Java

```java
new ObjectInputStream(in).readObject();
DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(in);
ZipInputStream zis; zis.getNextEntry(); Files.copy(..., Paths.get(dest, entry.getName()));
```

`XMLInputFactory` without `ACCESS_EXTERNAL_DTD` disabled; Apache POI on macro-enabled Office files.

### C#

```csharp
BinaryFormatter.Deserialize(stream);
new XmlDocument().Load(path);
ZipFile.ExtractToDirectory(archive, dest);
```

### JavaScript

```javascript
const zip = await JSZip.loadAsync(buffer);
zip.file(entry.name).async("uint8array");  // entry.name may contain ../
yaml.load(str);
```

### Go

```go
archive/zip.OpenReader(path)  // extract without filepath.Clean check
xml.Unmarshal(data, &v)  // verify decoder limits
```

### C / native

```c
unzip(file, dest_dir);  // no canonical path check
```

## Sample Vulnerable Code in Python

```python
import yaml
from flask import Flask, request

app = Flask(__name__)

@app.post("/import")
def import_config():
    data = request.files["file"].read()
    # Unsafe: yaml.load can construct arbitrary Python objects
    return yaml.load(data)
```

## Step-by-Step Review Walkthrough

1. **Inventory parsers.** List ZIP, TAR, XML, JSON with type tags, YAML, pickle, Java serialization, PDF, and image libraries in the change.
2. **Trace the Python YAML import.** In the sample, `yaml.load` without a safe loader enables arbitrary object construction from untrusted bytes.
3. **Check default parser settings.** Many XML and YAML loaders enable dangerous features unless explicitly disabled.
4. **Review archive extraction.** Paths containing `..` or absolute paths can escape the target directory (Zip Slip).
5. **Inspect limits on depth and size.** Cap compressed size, file count, and expanded bytes before parsing continues.
6. **Trace post-parse pipelines.** Parsed nodes must not feed `eval`, SpEL, or dynamic SQL without validation.
7. **Confirm least-privilege workers.** High-risk parsing should run in isolated processes when full format support is unavoidable.

## Risk Impact Analysis

**Remote code execution.** Pickle, Java serialization, and unsafe YAML loaders can execute attacker-chosen code during load.

**Local file read via XXE.** XML parsers with external entities enabled may read server files and embed them in responses.

**Denial of service.** ZIP bombs and unbounded decompression exhaust CPU and memory.

**Path escape on extract.** Archive members written outside the intended directory overwrite configuration or web roots.

## Vulnerable Examples in Other Languages

### Java

```java
public void importArchive(InputStream in) throws Exception {
    try (ZipInputStream zis = new ZipInputStream(in)) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            Path out = Paths.get("/var/import", entry.getName());
            Files.copy(zis, out, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}

public Config loadConfig(byte[] yamlBytes) {
    Yaml yaml = new Yaml(); // unsafe constructor — arbitrary object construction
    return yaml.load(new String(yamlBytes));
}
```

### C#

```csharp
public object LoadSession(byte[] blob)
{
    var formatter = new BinaryFormatter();
    using var ms = new MemoryStream(blob);
    return formatter.Deserialize(ms);
}

public void ImportXml(Stream upload)
{
    var doc = new XmlDocument();
    doc.XmlResolver = new XmlUrlResolver(); // XXE via external entities
    doc.Load(upload);
}
```

### Go

```go
func parseUpload(r io.Reader) error {
    dec := xml.NewDecoder(r)
    dec.Strict = false
    var doc any
    return dec.Decode(&doc)
}

func importArchive(path string) error {
    r, err := zip.OpenReader(path)
    if err != nil {
        return err
    }
    defer r.Close()
    for _, f := range r.File {
        target := filepath.Join("/var/import", f.Name)
        out, _ := os.Create(target) // zip slip — no containment check
        rc, _ := f.Open()
        io.Copy(out, rc)
    }
    return nil
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use `yaml.safe_load`. Validate archive member paths. Prefer JSON for config interchange.

```python
import zipfile
from pathlib import Path

import yaml
from flask import Flask, abort, request

app = Flask(__name__)
IMPORT_ROOT = Path("/var/import").resolve()

def safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    dest = dest.resolve()
    for member in zf.infolist():
        target = (dest / member.filename).resolve()
        if not target.is_relative_to(dest):
            raise ValueError("zip slip detected")
        zf.extract(member, dest)

@app.post("/import")
def import_config():
    data = request.files["file"].read()
    config = yaml.safe_load(data)
    if not isinstance(config, dict):
        abort(400)
    return {"keys": list(config.keys())}
```

```python
# XML when required — use defusedxml
from defusedxml import ElementTree as ET

tree = ET.fromstring(untrusted_xml_bytes)
```

**Important:** Never call `pickle.load` on upload bytes. Reject pickle magic regardless of extension.

### Java

Validate Zip Slip paths. Disable DTD and external entities in XML parsers.

```java
private void safeExtract(ZipInputStream zis, Path destDir) throws IOException {
    Path dest = destDir.toAbsolutePath().normalize();
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
        Path target = dest.resolve(entry.getName()).normalize();
        if (!target.startsWith(dest)) {
            throw new IOException("zip slip detected");
        }
        Files.copy(zis, target, StandardCopyOption.REPLACE_EXISTING);
    }
}
```

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

### C#

Avoid `BinaryFormatter`. Use `System.Text.Json` for known DTOs. Prohibit DTD in XML.

```csharp
public ConfigDto LoadConfig(string json)
{
    return JsonSerializer.Deserialize<ConfigDto>(json)
        ?? throw new JsonException("Invalid config");
}
```

```csharp
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
using var reader = XmlReader.Create(stream, settings);
```

### Go

Reject archive entries with `..` or absolute paths. Limit upload size before parse.

```go
func safeExtract(r io.Reader, dest string) error {
    data, err := io.ReadAll(io.LimitReader(r, 10<<20))
    if err != nil {
        return err
    }
    destAbs, err := filepath.Abs(dest)
    if err != nil {
        return err
    }
    zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
    if err != nil {
        return err
    }
    for _, f := range zr.File {
        target := filepath.Join(destAbs, f.Name)
        clean, err := filepath.Abs(filepath.Clean(target))
        if err != nil {
            return err
        }
        rel, err := filepath.Rel(destAbs, clean)
        if err != nil || strings.HasPrefix(rel, "..") {
            return fmt.Errorf("zip slip detected")
        }
        // extract f to clean with size limits
    }
    return nil
}
```

## Verify During Review

- No unsafe deserialization or YAML/XML loaders on attacker-controlled file bytes.
- Archive extraction validates every member path against a fixed base directory.
- Parser limits cap compressed size, entry count, and recursion depth.
- Parsed output is validated as data, not executed or reflected into code paths.
- Dangerous format features (macros, DTD, external entities) are disabled or rejected.
- High-risk parsing runs with minimal privileges and monitoring for anomalies.

## Reference

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [OWASP — Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [PyYAML — safe_load](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [Python defusedxml](https://pypi.org/project/defusedxml/)
- [Java DocumentBuilderFactory security features](https://docs.oracle.com/en/java/javase/21/docs/api/java.xml/module-summary.html)
- [Microsoft — BinaryFormatter obsolete](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)
- [Go archive/zip package](https://pkg.go.dev/archive/zip)
