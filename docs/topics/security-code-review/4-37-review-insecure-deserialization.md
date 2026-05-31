---
title: Review Insecure Deserialization
keywords:
  - security code review
  - insecure deserialization
  - object injection
  - pickle
  - Java serialization
  - CWE-502
description: How to read code for insecure deserialization where untrusted input can instantiate objects and execute attacker-controlled logic.
---

## 4.37 - Review Insecure Deserialization

Insecure deserialization appears when applications rebuild objects from untrusted byte streams or structured payloads without validation. Review Java `ObjectInputStream`, Python `pickle`, .NET `BinaryFormatter`, and YAML loaders that construct arbitrary types. Trace serialized data from cookies, caches, message queues, and file uploads to deserialization sinks.

## What This Vulnerability Is

Deserialization converts stored or transmitted data back into runtime objects. When the format allows arbitrary types—or when gadget chains exist in the classpath—attackers can craft payloads that execute code during deserialization. Native object serialization in Java and pickle in Python are high-risk; even JSON can be unsafe when polymorphic type metadata is honored blindly.

The unsafe assumption is that serialized data is trusted because it came from an internal service or was signed without verification. Attackers may tamper with cookies, replay messages, or upload malicious files. Mitigation starts with avoiding deserialization of user-controlled input, using safer formats, and keeping dependencies patched. This pattern maps to [CWE-502](https://cwe.mitre.org/data/definitions/502.html) (Deserialization of Untrusted Data).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Session restore, cache reload, import/export, inter-service messaging, plugin state |
| **Native serialization** | `ObjectInputStream`, `pickle.loads`, PHP `unserialize`, .NET `BinaryFormatter` |
| **Polymorphic parsers** | Jackson default typing, XStream, XMLDecoder without type allowlists |
| **Data sources** | HTTP cookies, hidden fields, Redis, Kafka, session stores, uploaded files |
| **Encrypted blobs** | Serialization wrapped in encryption without authentication or integrity checks |
| **Dependency risk** | commons-collections and similar gadget-bearing libraries on the classpath |
| **Safer alternatives missing** | JSON/protobuf into plain DTOs with schema validation not used |

## Sample Vulnerable Code in Python

```python
import pickle
import yaml
from flask import Flask, request

app = Flask(__name__)

@app.route("/import", methods=["POST"])
def import_state():
    # Attacker-controlled bytes execute arbitrary code during unpickling
    state = pickle.loads(request.get_data())
    return process(state)

@app.route("/config", methods=["POST"])
def load_config():
    # yaml.load without SafeLoader may construct arbitrary Python objects
    config = yaml.load(request.get_data(), Loader=yaml.Loader)
    apply_config(config)

def restore_session(cookie_value: bytes):
    return pickle.loads(cookie_value)
```

## Step-by-Step Review Walkthrough

1. **Search deserialization APIs.** Look for `ObjectInputStream`, `readObject`, `pickle.loads`, `yaml.load`, `BinaryFormatter`, and `unserialize`.
2. **Identify data sources.** Trace cookies, form fields, caches, message queues, session stores, and uploaded files to deserialization sinks.
3. **Check type metadata influence.** Review JSON `@type` fields, YAML tags, and XML entities that select arbitrary classes.
4. **Review classpath gadgets.** Outdated commons-collections and similar JARs raise exploitability even when input is partially trusted.
5. **Inspect encrypted blobs.** Encryption without authentication does not prevent tampering of serialized payloads.
6. **Confirm safer alternatives.** Prefer JSON or protobuf into plain DTOs with schema validation over object graphs.
7. **Verify dependency scanning.** Dependabot, OSV, or Snyk should cover libraries involved in deserialization paths.

## Risk Impact Analysis

**Remote code execution.** Gadget chains in Java and pickle opcodes in Python often achieve full process compromise from a single malicious blob.

**Authentication bypass.** Tampered session objects may elevate privileges or impersonate users when deserialized into application state.

**Lateral movement.** Message queue and cache deserialization flaws let attackers pivot through internal services.

**Data integrity loss.** Attackers may alter business objects in transit when integrity checks are absent.

**Difficult detection.** Deserialization exploits may leave few obvious log signatures compared to SQL injection or XSS.

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

## Verify During Review

- User-controlled input is not passed to native object deserialization APIs.
- JSON, XML, and YAML parsers use strict schemas, safe loaders, and disabled polymorphic type gadgets.
- Session and cache blobs use signed and authenticated formats, or store opaque server-side keys instead of serialized objects.
- Dependencies with known deserialization CVEs are patched or removed.
- Safer data formats (JSON with DTOs) replace Java serialization and pickle in cross-trust-boundary flows.
- Error handling does not echo serialized payload details that aid exploit crafting.

## Reference

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [JEP 290: Filter Incoming Serialization Data](https://openjdk.org/jeps/290)
- [Python pickle documentation — warning](https://docs.python.org/3/library/pickle.html)
- [PyYAML safe_load](https://pyyaml.org/wiki/PyYAMLDocumentation#loading-yaml)
- [pydantic validation](https://docs.pydantic.dev/latest/concepts/models/)
- [Gson user guide](https://google.github.io/gson/UserGuide.html)
- [System.Text.Json documentation](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/overview)
- [Go encoding/json Decoder.DisallowUnknownFields](https://pkg.go.dev/encoding/json#Decoder.DisallowUnknownFields)
