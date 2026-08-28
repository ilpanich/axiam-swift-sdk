#!/usr/bin/env python3
"""Generate the CONTRACT §27 management surface for the Swift SDK.

Reads ``management-registry.json`` (the 147 operations across 24 namespaces, maintained
in ``ilpanich/axiam`` and vendored here) plus ``openapi.json``, and writes:

- ``Sources/AxiamSDK/Management/Generated/ManagementModels.swift`` — one struct or enum
  per request and response type;
- ``Sources/AxiamSDK/Management/Generated/ManagementNamespaces.swift`` — the 24 namespace
  handles, their 147 operations, and the accessors that put them on ``AxiamClient``;
- ``Tests/AxiamSDKTests/ManagementGeneratedTests.swift`` — one conformance case per
  operation, plus a round-trip case per model and a both-ways case per enum.

Run with ``--check`` to verify the committed output is current; that is what CI runs.

Three things about Swift shape this generator commits to, all of them forced:

**Explicit ``Codable`` rather than synthesis.** Every model gets hand-written
``CodingKeys``, ``init(from:)`` and ``encode(to:)``. Two reasons. §27.4 rule 5 makes
"absent, not null" normative for a sparse update, and ``encodeIfPresent`` says that where
relying on what the compiler synthesises for an ``Optional`` says it only by convention.
And §27.5's request-side secrets have to reach the wire out of a ``Sensitive<T>`` that
this SDK deliberately does NOT make ``Codable`` — see below.

**``Sensitive<T>`` stays un-``Codable``.** ``Sources/AxiamSDK/Sensitive.swift`` is explicit
that conformance is withheld so that serialising a value can never emit the secret it
protects. Six request fields (§27.5) nonetheless have to send one. Rather than weaken the
type for everything, the generated ``encode(to:)`` calls ``.expose()`` on exactly those
six fields, at exactly the point the contract requires the secret on the wire. Every such
call site is generated from the registry's ``sensitive_request_fields``, so the set is a
property of the surface rather than a list somebody maintains.

**Handles are ``Sendable`` structs over the client actor.** ``AxiamClient`` is an actor and
CI builds one leg in Swift 6 language mode, where a cross-actor value that is not
``Sendable`` is an error rather than a warning. A handle therefore holds the actor (itself
``Sendable``) plus a scope of two optional strings, and every operation is ``async``. The
namespace accessors are ``nonisolated``, so ``try await client.roles.list()`` needs the one
``await`` §27.3's Swift row shows rather than two.
"""
from __future__ import annotations


import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REGISTRY: dict[str, Any] = json.loads((ROOT / "management-registry.json").read_text())
SPEC: dict[str, Any] = json.loads((ROOT / "openapi.json").read_text())
SCHEMAS: dict[str, Any] = SPEC["components"]["schemas"]

# §27.4 rule 3: `{org_id}` always defaults from the client. `{tenant_id}`
# defaults from the client only where it names the *context*; in `tenants` and
# the signing-CA routes it names the object being acted on.
IMPLICIT_TENANT_NAMESPACES = {"email_config", "settings", "webauthn_policy"}

# Swift has one module and no nested namespaces, so a generated model shares a name space
# with every type the hand-written SDK already declares -- and a collision there is a hard
# REDECLARATION error, not a shadowing warning.
#
# `OpaqueEnrollment` is the one that actually collides. §23 already models that exact wire
# shape (`Sources/AxiamSDK/Opaque/OpaqueWire.swift`) as an `Encodable`-only type with
# snake_case properties and no `CodingKeys`, which a §27 model embedding it would need to
# DECODE. Reusing it is therefore not possible, and renaming §23's would break its callers,
# so the §27 copy carries a prefix.
#
# `reserved_type_names()` turns any FUTURE collision into a generator failure rather than a
# redeclaration nobody sees until the build breaks; this map is where the rename goes.
RENAMED_SCHEMAS: dict[str, str] = {
    "OpaqueEnrollment": "ManagementOpaqueEnrollment",
}

EXAMPLE_UUID = "11111111-1111-4111-8111-111111111111"

# Deliberately different from EXAMPLE_UUID and from the fixture client's own scope, so a
# §27.4 rule 3 assertion can tell an override that took effect from one that was ignored.
OTHER_ORG = "22222222-2222-4222-8222-222222222222"
OTHER_TENANT = "33333333-3333-4333-8333-333333333333"
EXAMPLE_TIME = "2026-08-26T00:00:00Z"


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------


def pascal(text: str) -> str:
    """``service_accounts`` -> ``ServiceAccounts``; already-Pascal input is kept.

    Deliberately does NOT normalise initialisms, so every generated type name can be
    grepped straight out of ``openapi.json``.
    """
    if "_" not in text and "-" not in text and text[:1].isupper():
        return RENAMED_SCHEMAS.get(text, text)
    parts = [p for p in text.replace("-", "_").replace(" ", "_").split("_") if p]
    joined = "".join(p[0].upper() + p[1:] for p in parts)
    return RENAMED_SCHEMAS.get(joined, joined)


def camel(text: str) -> str:
    """``service_accounts`` -> ``serviceAccounts`` — §27.3's Swift casing."""
    out = pascal(text)
    return out[0].lower() + out[1:] if out else out


def snake(text: str) -> str:
    """``ServiceAccounts`` -> ``service_accounts``; already-snake input is kept."""
    out: list[str] = []
    for i, ch in enumerate(text):
        boundary = not text[i - 1].isupper() or (i + 1 < len(text) and text[i + 1].islower())
        if ch.isupper() and i and boundary:
            out.append("_")
        out.append(ch.lower())
    return "".join(out).replace("-", "_").replace("__", "_")


def wrap(text: str, width: int = 76) -> list[str]:
    """Reflow ``text`` into paragraph-preserving lines."""
    out: list[str] = []
    for para in str(text).strip().split("\n\n"):
        words = para.split()
        if not words:
            continue
        line = ""
        for word in words:
            if line and len(line) + 1 + len(word) > width:
                out.append(line)
                line = word
            else:
                line = f"{line} {word}" if line else word
        if line:
            out.append(line)
        out.append("")
    while out and out[-1] == "":
        out.pop()
    return out


def escape(text: str) -> str:
    """Make an ``openapi.json`` description safe to paste into a Swift comment.

    ``*/`` closes a block comment, so a description carrying one would spill the rest of
    itself into code. Both ``*/`` and ``/*`` are neutralised. The emitters here use
    ``//`` and ``///``, where neither can do harm -- this keeps that true if one ever
    moves to a block comment.
    """
    out = " ".join(str(text).split())
    return out.replace("*/", "* /").replace("/*", "/ *")


def resolve_ref(schema: Any) -> Any:
    """Follow ``$ref`` chains to the schema they name."""
    node = schema
    while isinstance(node, dict) and "$ref" in node:
        node = SCHEMAS.get(node["$ref"].split("/")[-1], {})
    return node


def nullable_ref(schema: Any) -> str | None:
    """``{oneOf: [{type: null}, {$ref: X}]}`` -- utoipa's optional-enum shape."""
    variants = schema.get("oneOf") if isinstance(schema, dict) else None
    if not isinstance(variants, list) or len(variants) != 2:
        return None
    nulls = [v for v in variants if v.get("type") == "null"]
    refs = [v for v in variants if "$ref" in v]
    return refs[0]["$ref"].split("/")[-1] if len(nulls) == 1 and len(refs) == 1 else None


def flatten(name: str) -> tuple[dict[str, Any], set[str], str | None]:
    """Properties, required set and description of ``name``, ``allOf`` resolved."""
    props: dict[str, Any] = {}
    required: set[str] = set()

    def absorb(node: Any) -> None:
        """Merge one ``allOf`` member's properties into the accumulator."""
        resolved = resolve_ref(node) if "$ref" in node else node
        props.update(resolved.get("properties") or {})
        required.update(resolved.get("required") or [])
        for sub in resolved.get("allOf") or []:
            absorb(sub)

    schema = SCHEMAS.get(name, {})
    absorb(schema)
    return props, required, schema.get("description")


def discriminated(schema: Any) -> tuple[str, list[tuple[str, Any]]] | None:
    """Detect an internally-tagged union and return ``(tag, [(value, payload)])``."""
    variants = schema.get("oneOf")
    if not isinstance(variants, list) or len(variants) < 2:
        return None
    tag: str | None = None
    arms: list[tuple[str, Any]] = []
    for variant in variants:
        parts = variant.get("allOf") or [variant]
        value: str | None = None
        payload: Any = None
        leftovers: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
        for part in parts:
            if "$ref" in part:
                payload = part
                continue
            for pname, pschema in (part.get("properties") or {}).items():
                enum = pschema.get("enum")
                if pschema.get("type") == "string" and isinstance(enum, list) and len(enum) == 1:
                    if tag and tag != pname:
                        return None
                    tag = pname
                    value = enum[0]
                else:
                    leftovers["properties"][pname] = pschema
                    if pname in (part.get("required") or []):
                        leftovers["required"].append(pname)
        if value is None:
            return None
        arms.append((value, payload if payload is not None else leftovers))
    return (tag or "", arms)


def sensitive_map() -> dict[str, set[str]]:
    """Which fields of which schemas carry a secret, per the registry."""
    out: dict[str, set[str]] = {}
    for ns in REGISTRY["namespaces"].values():
        for op in ns["operations"].values():
            if op["request_schema"] and op["sensitive_request_fields"]:
                key = op["request_schema"].lstrip("[]")
                out.setdefault(key, set()).update(op["sensitive_request_fields"])
            if op["response"]["schema"] and op["sensitive_response_fields"]:
                key = op["response"]["schema"].lstrip("[]")
                out.setdefault(key, set()).update(op["sensitive_response_fields"])
    return out


def schema_closure() -> list[str]:
    """Every schema reachable from an operation, transitively, sorted."""
    seeds: set[str] = set()
    for ns in REGISTRY["namespaces"].values():
        for op in ns["operations"].values():
            if op["request_schema"]:
                seeds.add(op["request_schema"].lstrip("[]"))
            if op["response"]["schema"]:
                seeds.add(op["response"]["schema"].lstrip("[]"))

    def refs_in(node: Any, found: set[str]) -> None:
        """Collect every ``$ref`` target name appearing anywhere under ``node``."""
        if isinstance(node, list):
            for item in node:
                refs_in(item, found)
        elif isinstance(node, dict):
            if "$ref" in node:
                found.add(node["$ref"].split("/")[-1])
            for value in node.values():
                refs_in(value, found)

    seen: set[str] = set()
    frontier = list(seeds)
    while frontier:
        name = frontier.pop()
        if name in seen or name not in SCHEMAS:
            continue
        seen.add(name)
        found: set[str] = set()
        refs_in(SCHEMAS[name], found)
        frontier.extend(f for f in found if f not in seen)
    return sorted(seen)


def _classify() -> tuple[set[str], set[str]]:
    """Split the spec's schemas into (enums, discriminated unions), by RENDERED name.

    Computed once, up front. A type's NAME never tells you its KIND, and an emitter that
    re-guesses from a name is how a sibling port shipped `Enum::fromArray()` on a backed
    enum.
    """
    enums: set[str] = set()
    unions: set[str] = set()
    for name, schema in SCHEMAS.items():
        if not isinstance(schema, dict):
            continue
        if isinstance(schema.get("enum"), list):
            enums.add(pascal(name))
        elif discriminated(schema):
            unions.add(pascal(name))
    return enums, unions


ENUMS, UNIONS = _classify()


# ---------------------------------------------------------------------------
# Swift naming and types
# ---------------------------------------------------------------------------

MODELS_SWIFT = "Sources/AxiamSDK/Management/Generated/ManagementModels.swift"
OPS_SWIFT = "Sources/AxiamSDK/Management/Generated/ManagementNamespaces.swift"
TESTS_SWIFT = "Tests/AxiamSDKTests/ManagementGeneratedTests.swift"

BANNER = """// Generated by Scripts/gen_management.py from management-registry.json and openapi.json.
// DO NOT EDIT — your changes will be overwritten. Regenerate with
// `python3 Scripts/gen_management.py`; CI verifies the committed output is current.
"""

# Reserved in Swift where a declaration name would land. Escaped with backticks rather
# than renamed: `client.default` reads as the wire field it is, and a renamed property
# would have to be remembered by every caller and by the CodingKeys beside it.
SWIFT_KEYWORDS = {
    "associatedtype", "class", "deinit", "enum", "extension", "fileprivate", "func",
    "import", "init", "inout", "internal", "let", "operator", "private", "protocol",
    "public", "rethrows", "static", "struct", "subscript", "typealias", "var",
    "break", "case", "continue", "default", "defer", "do", "else", "fallthrough",
    "for", "guard", "if", "in", "repeat", "return", "switch", "where", "while",
    "as", "catch", "false", "is", "nil", "super", "self", "Self", "throw", "throws",
    "true", "try", "actor", "async", "await", "some", "any", "Type", "Protocol",
}

_TYPE_DECLARATION = re.compile(
    r"^(?:public |internal |private |fileprivate )?(?:final )?"
    r"(?:struct|class|enum|actor|protocol|typealias)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)


def reserved_type_names() -> set[str]:
    """Every type the HAND-WRITTEN sources declare.

    Swift has one module and no nested namespaces, so a generated model that renders to one
    of these names is a redeclaration — a hard error, and one whose diagnostic points at the
    generated file rather than at the registry entry that caused it. Scanning is better than
    a hand-maintained list precisely because the list would rot: a type added to the SDK
    next year is caught here, at the moment somebody regenerates, with a message naming the
    schema and the fix.

    A regex, not a parser: it only has to find declaration lines, and a false positive
    (which would demand a rename that was not strictly necessary) is a far cheaper mistake
    than a false negative.
    """
    names: set[str] = set()
    for path in sorted((ROOT / "Sources" / "AxiamSDK").rglob("*.swift")):
        if "Management" in path.parts or path.name.startswith("Management"):
            continue
        names.update(_TYPE_DECLARATION.findall(path.read_text()))
    # The hand-written half of §27 lives under Management/ and is skipped above, since the
    # GENERATED half lives there too and would otherwise reserve its own names.
    names.update({
        "Page", "PageRequest", "CallScope", "ManagementJSON", "ManagementCodec",
        "ManagementFailure", "Manifest", "ManifestEntity", "ManifestKind", "ChangeAction",
        "PlannedChange", "ManagementPlan", "ApplyReport", "ManifestError", "ManifestApi",
        "ManifestBuilder", "Declare", "ManagementApi",
    })
    return names


RESERVED_TYPES = reserved_type_names()


def ident(name: str) -> str:
    """A Swift identifier, back-ticked when it collides with a keyword."""
    return f"`{name}`" if name in SWIFT_KEYWORDS else name


# Initialisms the Swift API Design Guidelines want cased uniformly — `tenantID`, not
# `tenantId`, matching `AxiamConfig.tenantID` and `AuthzError.resourceID` in the
# hand-written half. Curated rather than heuristic: a rule that uppercased every
# three-letter fragment would produce `keyALGorithm`.
INITIALISMS = {
    "id", "url", "uri", "api", "ca", "pem", "pgp", "scim", "saml", "oidc", "sso",
    "smtp", "hmac", "totp", "mfa", "jwt", "ttl", "dns", "ip", "tls", "csr", "crl",
    "uuid", "mds", "pkce", "dpop", "rp", "cn",
}


def swift_case(name: str, upper_first: bool = False) -> str:
    """Wire name -> Swift identifier, with initialisms cased uniformly.

    An initialism is uppercased wherever it appears except at the very start of a
    lowerCamelCase name, where the guidelines say it goes fully lowercase (`urlPath`,
    not `URLPath`).
    """
    parts = [p for p in re.split(r"[-_ ]+", name) if p]
    if not parts:
        return name
    out: list[str] = []
    for index, part in enumerate(parts):
        lowered = part.lower()
        leading = index == 0 and not upper_first
        if lowered in INITIALISMS:
            out.append(lowered if leading else lowered.upper())
        elif leading:
            out.append(lowered if part.isupper() else part[0].lower() + part[1:])
        else:
            out.append(part[0].upper() + part[1:])
    return "".join(out)


def prop(name: str) -> str:
    """``service_accounts`` -> ``serviceAccounts`` — §27.3's Swift casing."""
    return ident(swift_case(name))


def field(name: str) -> str:
    """A model property name: the wire name in camelCase, keyword-escaped."""
    return ident(swift_case(name))


def handle_type(namespace: str) -> str:
    """``service_accounts`` -> ``ServiceAccountsApi``."""
    return pascal(namespace) + "Api"


def model_type(name: str) -> str:
    """The Swift type for a schema, refusing a collision with a hand-written type."""
    rendered = pascal(name)
    if rendered in RESERVED_TYPES:
        raise SystemExit(
            f"schema {name!r} renders as {rendered!r}, which the hand-written sources "
            "already declare. Swift has one module and no nested namespaces, so emitting "
            "it would be a redeclaration. Add an entry to RENAMED_SCHEMAS."
        )
    return rendered


def enum_case(value: str) -> str:
    """A Swift enum case name for one wire value."""
    return ident(swift_case(value))


def doc(text: str, indent: str = "", width: int = 96) -> list[str]:
    """A `///` documentation comment, wrapped. Empty text is a blank doc line."""
    body = wrap(text, width - len(indent) - 4)
    if not body:
        return [f"{indent}///"]
    return [f"{indent}///" if not line else f"{indent}/// {line}" for line in body]


def comment(text: str, indent: str = "", width: int = 96) -> list[str]:
    """A `//` comment, wrapped."""
    body = wrap(text, width - len(indent) - 3)
    return [f"{indent}//" if not line else f"{indent}// {line}" for line in body]


def swift_field(schema: Any, secret: bool = False) -> dict[str, str]:
    """Map a schema to ``(type, kind)`` for one model property."""
    if secret:
        return {"decl": "Sensitive<String>", "kind": "sensitive", "ref": ""}
    if not isinstance(schema, dict):
        return {"decl": "ManagementJSON", "kind": "json", "ref": ""}

    if "$ref" in schema:
        name = model_type(schema["$ref"].split("/")[-1])
        return {"decl": name, "kind": "enum" if name in ENUMS else "model", "ref": name}

    inner = nullable_ref(schema)
    if inner:
        name = model_type(inner)
        return {"decl": name, "kind": "enum" if name in ENUMS else "model", "ref": name}

    if isinstance(schema.get("allOf"), list) and len(schema["allOf"]) == 1:
        return swift_field(schema["allOf"][0])

    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), None)

    if kind == "array":
        item = swift_field(schema.get("items") or {})
        return {"decl": f"[{item['decl']}]", "kind": "array", "ref": item["ref"],
                "element": item["decl"], "element_kind": item["kind"]}
    if kind == "integer":
        return {"decl": "Int", "kind": "int", "ref": ""}
    if kind == "number":
        return {"decl": "Double", "kind": "double", "ref": ""}
    if kind == "boolean":
        return {"decl": "Bool", "kind": "bool", "ref": ""}
    if kind == "string":
        return {"decl": "String", "kind": "string", "ref": ""}

    # A free-form object keeps its JSON shape. `ManagementJSON` round-trips it exactly,
    # which matters because the server round-trips it too: inventing a Swift type for
    # `metadata` would drop every key this SDK did not know to declare.
    return {"decl": "ManagementJSON", "kind": "json", "ref": ""}


PROJECTION_DOC = (
    "Resolved by the list projection only.\n\n"
    "The server resolves this for a whole page in one query, so it is populated by "
    "`list` and is `nil` on `get` (CONTRACT.md \u00a727.11 rule 4). `nil` there means "
    "\"this read does not carry it\", not \"there is nothing bound\" \u2014 this SDK does "
    "not issue a second request to fill it in."
)


def projection_map() -> dict[str, list[dict[str, Any]]]:
    """Fields a list projection ADDS to its base schema, keyed by the base's name.

    \u00a727.11 rule 4: the server expresses a projection as an ``allOf`` of the named base
    and an anonymous object, so the added property belongs to no schema in
    ``components``. The registry records it as ``response.projected_fields``; this folds
    it back onto the base model as an OPTIONAL property, which is what makes it ``nil``
    on the ``get`` that does not project it rather than absent from the type.
    """
    added: dict[str, list[dict[str, Any]]] = {}
    for ns in REGISTRY["namespaces"].values():
        for op in ns["operations"].values():
            response = op.get("response") or {}
            extras = response.get("projected_fields") or []
            base = (response.get("schema") or "").lstrip("[]")
            if not extras or not base:
                continue
            known = {f["name"] for f in added.setdefault(base, [])}
            for extra in extras:
                if extra["name"] not in known:
                    added[base].append(extra)
    return added


PROJECTED: dict[str, list[dict[str, Any]]] = projection_map()


def fields_of(schema_name: str, secrets: set[str]) -> tuple[list[dict[str, Any]], str | None]:
    """Every property of ``schema_name``, in the spec's own order.

    A discriminated union gets two synthetic properties: the discriminator, and the whole
    object as `ManagementJSON`. Swift could model a sum type with an enum, but the arms
    here are open-ended server shapes — an enum would have to be regenerated and would
    break every `switch` the moment the server grew an arm, where the tag plus payload
    simply carries the new one through.
    """
    schema = SCHEMAS.get(schema_name) or {}
    union = discriminated(schema)
    if union:
        tag, _arms = union
        return ([
            {"wire": tag, "name": field(tag), "decl": "String", "kind": "string",
             "ref": "", "required": True, "schema": {"type": "string"}, "secret": False,
             "description": f"The `{tag}` discriminator naming which variant this is."},
            {"wire": "", "name": "raw", "decl": "ManagementJSON", "kind": "union_raw",
             "ref": "", "required": True, "schema": {}, "secret": False,
             "description": "The whole object as the server sent it, to read the "
                            f"variant's own fields from once `{tag}` says which it is."},
        ], schema.get("description"))

    props, required, description = flatten(schema_name)
    props = dict(props)
    for extra in PROJECTED.get(schema_name, []):
        if extra["name"] in props:
            continue
        # Never added to `required`: the whole point is that the operation which does NOT
        # project it still decodes, with the property nil (\u00a727.11 rule 4).
        props[extra["name"]] = {
            "type": extra["type"],
            "format": extra.get("format"),
            "description": extra.get("description") or PROJECTION_DOC,
        }
    out: list[dict[str, Any]] = []
    for wire, sub in props.items():
        info = swift_field(sub, secret=wire in secrets)
        out.append({
            "wire": wire, "name": field(wire), "decl": info["decl"], "kind": info["kind"],
            "ref": info["ref"], "required": wire in required, "schema": sub,
            "secret": wire in secrets,
            "description": sub.get("description") if isinstance(sub, dict) else None,
        })
    return out, description


def declared(f: dict[str, Any]) -> str:
    """How one property is declared; an optional one wears `?`.

    `Optional` rather than a sentinel: it says "absent" in the type, so §27.4 rule 5's
    "an unset field is OMITTED, not null" is something `encodeIfPresent` can act on
    without a convention to remember.
    """
    return f["decl"] if f["required"] else f"{f['decl']}?"


def field_doc(f: dict[str, Any]) -> str:
    """The one-line description for a property."""
    if f["description"]:
        return escape(f["description"])
    if f["secret"]:
        return f"The server's `{f['wire']}` field — a ONE-TIME secret (§27.5)."
    return f"The server's `{f['wire']}` field."


def modelled() -> list[tuple[str, str, list[dict[str, Any]]]]:
    """Every schema that becomes a struct, with its properties."""
    secrets = sensitive_map()
    out = []
    for name in schema_closure():
        rendered = pascal(name)
        if rendered in ENUMS:
            continue
        fields, _desc = fields_of(name, secrets.get(name, set()))
        out.append((name, rendered, fields))
    return out


def enum_values(name: str) -> list[str]:
    """The wire values of an enum schema, in spec order."""
    return [str(v) for v in ((SCHEMAS.get(name) or {}).get("enum") or [])]


def method(name: str) -> str:
    """An operation's Swift method name — camelCase, keyword-escaped.

    `list` is the single most common §27 operation name and is a perfectly good Swift
    method name, so unlike the PHP and Go ports nothing needs a disambiguating suffix here.
    """
    return ident(swift_case(name))


# ---------------------------------------------------------------------------
# Operation plumbing
# ---------------------------------------------------------------------------

EXAMPLE_TIME = "2026-08-26T00:00:00Z"


def path_params(op: dict[str, Any]) -> list[str]:
    return re.findall(r"\{([^}]+)\}", op["path"])


def implicit_of(namespace: str, op: dict[str, Any]) -> set[str]:
    """Which path parameters the SDK fills in from the client (§27.4 rule 3)."""
    names = set(path_params(op))
    out = {"org_id"} & names
    if "tenant_id" in names and namespace in IMPLICIT_TENANT_NAMESPACES:
        out.add("tenant_id")
    return out


def op_params(namespace: str, op: dict[str, Any]) -> list[dict[str, Any]]:
    """The Swift parameter list for one operation, required before defaulted."""
    implicit = implicit_of(namespace, op)
    params: list[dict[str, Any]] = []

    for name in path_params(op):
        if name in implicit:
            continue
        params.append({"name": field(name), "type": "String", "kind": "path",
                       "wire": name, "required": True,
                       "text": f"The `{{{name}}}` path parameter."})

    for q in op["query_params"]:
        if op["paginated"] and q["name"] in {"offset", "limit", "search"}:
            continue
        if q["required"]:
            params.append({"name": field(q["name"]), "type": "String", "kind": "query",
                           "wire": q["name"], "required": True,
                           "text": f"The required `{q['name']}` query parameter."})

    if op["request_body"] != "none" and op["request_schema"]:
        params.append({"name": "body", "type": model_type(op["request_schema"].lstrip("[]")),
                       "kind": "body", "wire": "", "required": True,
                       "text": "The request body."})

    if op["paginated"]:
        params.append({"name": "page", "type": "PageRequest", "kind": "page", "wire": "",
                       "required": False, "default": "PageRequest()",
                       "text": "Which page to fetch; defaults to the first."})

    for q in op["query_params"]:
        if op["paginated"] and q["name"] in {"offset", "limit", "search"}:
            continue
        if not q["required"]:
            params.append({"name": field(q["name"]), "type": "String?", "kind": "query",
                           "wire": q["name"], "required": False, "default": "nil",
                           "text": f"The optional `{q['name']}` query parameter."})

    return params


def response_swift(op: dict[str, Any]) -> str:
    """The operation's return type."""
    kind = op["response"]["kind"]
    schema = op["response"]["schema"]
    if kind == "none" or not schema:
        return "Void"
    model = model_type(schema.lstrip("[]"))
    if kind == "page":
        return f"Page<{model}>"
    if kind == "array":
        return f"[{model}]"
    return model


def op_summary(op: dict[str, Any]) -> str:
    """The one-line summary for one operation, from the spec."""
    entry = (SPEC.get("paths") or {}).get(op["path"]) or {}
    node = entry.get(op["method"].lower()) or {}
    text = node.get("summary") or node.get("description") or ""
    return escape(text) if text else f"`{op['method']} {op['path']}`."


def example_json(schema: Any, depth: int = 0) -> Any:
    """A plausible wire value for ``schema`` -- what the fake transport returns."""
    if depth > 6 or not isinstance(schema, dict):
        return None
    if "$ref" in schema:
        return example_for(schema["$ref"].split("/")[-1], depth + 1)
    inner = nullable_ref(schema)
    if inner:
        return example_for(inner, depth + 1)
    if isinstance(schema.get("allOf"), list) and len(schema["allOf"]) == 1:
        return example_json(schema["allOf"][0], depth)
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), None)
    if kind == "array":
        return [example_json(schema.get("items") or {}, depth + 1)]
    if kind == "integer":
        return 1
    if kind == "number":
        return 1.5
    if kind == "boolean":
        return True
    if kind == "string":
        fmt = schema.get("format")
        if fmt == "uuid":
            return EXAMPLE_UUID
        if fmt == "date-time":
            return EXAMPLE_TIME
        return "example"
    if kind == "object" or "properties" in schema or "additionalProperties" in schema:
        return {k: example_json(v, depth + 1) for k, v in (schema.get("properties") or {}).items()}
    return {}


def example_for(name: str, depth: int = 0) -> Any:
    """A plausible wire object for the named schema."""
    if depth > 6:
        return None
    schema = SCHEMAS.get(name) or {}
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    union = discriminated(schema)
    if union:
        tag, arms = union
        value, payload = arms[0]
        resolved = resolve_ref(payload) if "$ref" in payload else payload
        out = {tag: value}
        for k, sub in (resolved.get("properties") or {}).items():
            out[k] = example_json(sub, depth + 1)
        return out
    props, _, _ = flatten(name)
    return {k: example_json(v, depth + 1) for k, v in props.items()}


def example_response(op: dict[str, Any]) -> Any:
    """The body the fake transport returns, honouring ``response.kind``.

    Reads ``response.kind`` and never infers plurality from the schema NAME -- the
    registry's ``response.schema`` carries no ``[]`` prefix, so a generator guessing from
    the name types all 13 bare-array reads as single objects.
    """
    kind = op["response"]["kind"]
    schema = op["response"]["schema"]
    if kind == "none" or not schema:
        return None
    body = example_for(schema.lstrip("[]"))
    if kind == "page":
        return {"items": [body], "total": 1, "offset": 0, "limit": 50}
    if kind == "array":
        return [body]
    return body


def swift_string(text: str) -> str:
    """A Swift string literal for arbitrary text, including JSON."""
    escaped = (text.replace("\\", "\\\\").replace('"', '\\"')
                   .replace("\n", "\\n").replace("\t", "\\t")
                   .replace("\r", "\\r"))
    return f'"{escaped}"'


def expected_path(op: dict[str, Any]) -> str:
    return re.sub(r"\{[^}]+\}", EXAMPLE_UUID, op["path"])


# ---------------------------------------------------------------------------
# Generated: models
# ---------------------------------------------------------------------------


def decode_expr(f: dict[str, Any]) -> list[str]:
    """The `init(from:)` line(s) for one property."""
    name, key, decl = f["name"], f["name"], f["decl"]
    if f["kind"] == "union_raw":
        return [f"        self.{name} = try ManagementJSON(from: decoder)"]
    if f["kind"] == "sensitive":
        if f["required"]:
            return [f"        self.{name} = Sensitive(try container.decode(String.self, "
                    f"forKey: .{key}))"]
        return [
            f"        if let raw = try container.decodeIfPresent(String.self, forKey: .{key}) {{",
            f"            self.{name} = Sensitive(raw)",
            "        } else {",
            f"            self.{name} = nil",
            "        }",
        ]
    if f["required"]:
        return [f"        self.{name} = try container.decode({decl}.self, forKey: .{key})"]
    return [f"        self.{name} = try container.decodeIfPresent({decl}.self, forKey: .{key})"]


def encode_expr(f: dict[str, Any]) -> list[str]:
    """The `encode(to:)` line(s) for one property."""
    name, key = f["name"], f["name"]
    if f["kind"] == "union_raw":
        return [f"        try {name}.encode(to: encoder)"]
    if f["kind"] == "sensitive":
        # §27.5 rule 1: the field is Sensitive in the model, and §27.5's request-side rows
        # require it on the wire all the same. `Sensitive` is deliberately not `Codable`
        # (see Sources/AxiamSDK/Sensitive.swift), so the unwrap is explicit and local — one
        # generated call site per registry-declared secret, and nowhere else.
        if f["required"]:
            return [f"        try container.encode({name}.expose(), forKey: .{key})"]
        return [f"        try container.encodeIfPresent({name}?.expose(), forKey: .{key})"]
    if f["required"]:
        return [f"        try container.encode({name}, forKey: .{key})"]
    # §27.4 rule 5: an unset field is ABSENT, not null. `encodeIfPresent` is what says so.
    return [f"        try container.encodeIfPresent({name}, forKey: .{key})"]


def emit_models() -> str:
    """One `struct` or `enum` per schema, with explicit `Codable`."""
    out = [BANNER, "import Foundation", ""]
    out.extend(comment(
        "CONTRACT.md §27 model types — one per request and response schema in "
        "`management-registry.json`, plus everything they reach transitively in "
        "`openapi.json`.\n\n"
        "`Codable` is written out rather than synthesised. §27.4 rule 5 makes \"absent, "
        "not null\" normative for a sparse update, and `encodeIfPresent` says that where "
        "relying on synthesis says it only by convention. And §27.5's request-side secrets "
        "have to reach the wire out of a `Sensitive<T>` this SDK deliberately does not make "
        "`Codable` — so those six fields unwrap explicitly, at exactly the point the "
        "contract puts the secret on the wire, and nowhere else."))
    out.append("")

    # ---- enums ----
    for name in schema_closure():
        rendered = pascal(name)
        if rendered not in ENUMS:
            continue
        values = enum_values(name)
        if not values:
            continue
        cases = {}
        for value in values:
            case = enum_case(value)
            if case in cases:
                raise SystemExit(
                    f"enum {rendered}: wire values {cases[case]!r} and {value!r} both render "
                    f"as case {case!r}. Two cases cannot share a name."
                )
            cases[case] = value

        description = (SCHEMAS.get(name) or {}).get("description")
        out.extend(doc(escape(description) if description
                       else f"The `{name}` enumeration, as the server spells it."))
        if "unknown" in cases:
            raise SystemExit(
                f"enum {rendered}: the spec declares a value rendering as case 'unknown', "
                "which collides with the open-enum carrier this generator adds."
            )
        out.extend(doc(""))
        out.extend(doc(
            "An **open** enum. A value this SDK's copy of the spec does not list decodes to "
            "`.unknown` rather than failing the response it arrived in (CONTRACT.md \u00a727.11 "
            "rule 1). Throwing there fails the WHOLE response, so one field of one record "
            "would take down the page it was on, including the records the caller did ask "
            "for."))
        out.extend(doc(""))
        out.extend(doc(
            "It is never read as one of the KNOWN cases: reading a new value as whichever "
            "case happens to be first turns a new server state into a wrong one, and on this "
            "surface these values gate access. `.unknown`'s own raw value is the empty "
            "string, which no server value is, so carrying an unrecognised value back into "
            "an update is refused by the server rather than written as a spelling it never "
            "used. A `switch` over these cases needs an `.unknown` arm."))
        out.append(f"public enum {rendered}: String, Codable, Sendable, CaseIterable {{")
        for case, value in cases.items():
            out.append(f'    case {case} = "{value}"')
        out.extend(doc("A value this SDK's copy of the spec does not list; see the type's "
                       "summary.", "    "))
        out.append('    case unknown = ""')
        out.append("")
        out.extend(doc("Decodes an unrecognised value to `.unknown` instead of throwing.\n\n"
                       "The synthesised `RawRepresentable` initializer stays strict \u2014 "
                       "`init(rawValue:)` is still `nil` for a value that is not a case \u2014 "
                       "so code that deliberately parses a raw string keeps its check. Only "
                       "DECODING, where the alternative is failing a whole response, is "
                       "lenient.", "    "))
        out.append("    public init(from decoder: any Decoder) throws {")
        out.append("        let raw = try decoder.singleValueContainer().decode(String.self)")
        out.append(f"        self = {rendered}(rawValue: raw) ?? .unknown")
        out.append("    }")
        out.append("}")
        out.append("")

    # ---- structs ----
    secrets = sensitive_map()
    for name in schema_closure():
        rendered = pascal(name)
        if rendered in ENUMS:
            continue
        fields, description = fields_of(name, secrets.get(name, set()))
        rendered = model_type(name)

        out.extend(doc(escape(description) if description
                       else f"The `{name}` schema."))
        out.append(f"public struct {rendered}: Codable, Sendable {{")

        for f in fields:
            out.extend(doc(field_doc(f), "    "))
            out.append(f"    public let {f['name']}: {declared(f)}")
            out.append("")

        # memberwise init — Swift synthesises one, but only `internal`, and a public struct
        # in a library that consumers cannot construct is a request body nobody can send.
        args = []
        for f in fields:
            suffix = "" if f["required"] else " = nil"
            args.append(f"{f['name']}: {declared(f)}{suffix}")
        if args:
            out.append("    public init(")
            for i, arg in enumerate(args):
                out.append(f"        {arg}" + ("," if i < len(args) - 1 else ""))
            out.append("    ) {")
            for f in fields:
                out.append(f"        self.{f['name']} = {f['name']}")
            out.append("    }")
        else:
            out.append("    public init() {}")
        out.append("")

        keyed = [f for f in fields if f["kind"] != "union_raw"]
        if keyed:
            out.append("    enum CodingKeys: String, CodingKey {")
            for f in keyed:
                out.append(f'        case {f["name"]} = "{f["wire"]}"')
            out.append("    }")
            out.append("")

        out.append("    public init(from decoder: any Decoder) throws {")
        if keyed:
            out.append("        let container = try decoder.container(keyedBy: CodingKeys.self)")
        for f in fields:
            out.extend(decode_expr(f))
        if not fields:
            out.append("        _ = decoder")
        out.append("    }")
        out.append("")

        out.append("    public func encode(to encoder: any Encoder) throws {")
        if any(f["kind"] == "union_raw" for f in fields):
            out.extend(comment(
                "A union is forwarded EXACTLY as received. Re-encoding from the one member "
                "this SDK models would drop every field belonging to the variant it does "
                "not model — and the server round-trips those.", "        "))
            for f in fields:
                if f["kind"] == "union_raw":
                    out.extend(encode_expr(f))
        else:
            if keyed:
                out.append("        var container = encoder.container(keyedBy: CodingKeys.self)")
            for f in fields:
                out.extend(encode_expr(f))
            if not fields:
                out.append("        _ = encoder")
        out.append("    }")
        out.append("}")
        out.append("")

    return "\n".join(out).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Generated: namespace handles and operations
# ---------------------------------------------------------------------------


def emit_operation(namespace: str, opname: str, op: dict[str, Any]) -> list[str]:
    """One `public func` on a namespace handle."""
    params = op_params(namespace, op)
    implicit = implicit_of(namespace, op)
    ret = response_swift(op)
    out: list[str] = []

    route = f"`{op['method']} {op['path']}`"
    summary = op_summary(op)
    out.extend(doc(summary, "    "))
    if summary.rstrip(".") != route:
        out.extend(doc("", "    "))
        out.extend(doc(route, "    "))
    if op["response"]["kind"] == "page":
        out.extend(doc("", "    "))
        out.extend(doc(
            "Returns ONE page. `Page.total` is the server's count across every page and is "
            "not `items.count`; call again with `page.next()` and stop when a page comes "
            "back empty (§27.4 rule 4).", "    "))
    if op["sensitive_response_fields"]:
        out.extend(doc("", "    "))
        fields = ", ".join(f"`{f}`" for f in op["sensitive_response_fields"])
        out.extend(doc(
            f"**Returned once (§27.5 rule 3).** {fields} is not stored server-side and no "
            "later `get` will return it again. A caller who discards this result because "
            "they can \"fetch it later\" has destroyed the credential — the corresponding "
            "`get` returns the non-secret projection with no indication anything is "
            "missing.", "    "))
    if params:
        out.extend(doc("", "    "))
    for p in params:
        out.extend(doc(f"- Parameter {p['name'].strip('`')}: {p['text']}", "    "))

    signature = []
    for p in params:
        default = f" = {p['default']}" if not p["required"] else ""
        signature.append(f"{p['name']}: {p['type']}{default}")
    joined = ", ".join(signature)
    ret_clause = "" if ret == "Void" else f" -> {ret}"
    if len(f"    public func {method(opname)}({joined}) async throws{ret_clause} {{") <= 100:
        out.append(f"    public func {method(opname)}({joined}) async throws{ret_clause} {{")
    else:
        out.append(f"    public func {method(opname)}(")
        for i, arg in enumerate(signature):
            out.append(f"        {arg}" + ("," if i < len(signature) - 1 else ""))
        out.append(f"    ) async throws{ret_clause} {{")

    path_args = [p for p in params if p["kind"] == "path"]
    if path_args:
        pairs = ", ".join(f'"{p["wire"]}": {p["name"]}' for p in path_args)
        out.append(f"        let pathParameters = [{pairs}]")
    else:
        out.append("        let pathParameters: [String: String] = [:]")

    query_required = [p for p in params if p["kind"] == "query" and p["required"]]
    query_optional = [p for p in params if p["kind"] == "query" and not p["required"]]
    appends = bool(query_required or query_optional)
    if op["paginated"]:
        keyword = "var" if appends else "let"
        out.append(f"        {keyword} query: [(String, String)] = page.queryPairs")
    elif appends:
        out.append("        var query: [(String, String)] = []")
    else:
        out.append("        let query: [(String, String)] = []")
    for p in query_required:
        out.append(f'        query.append(("{p["wire"]}", {p["name"]}))')
    for p in query_optional:
        # An unset filter is OMITTED, never sent empty: `?action=` is a filter matching
        # nothing, which is a different request from not filtering.
        out.append(f"        if let {p['name'].strip('`')} = {p['name']} {{")
        out.append(f'            query.append(("{p["wire"]}", {p["name"].strip("`")}))')
        out.append("        }")

    body_param = next((p for p in params if p["kind"] == "body"), None)
    if body_param:
        out.append(f"        let payload = try ManagementCodec.encode({body_param['name']})")
    else:
        out.append("        let payload: Data? = nil")

    out.append("        let data = try await client.managementSend(")
    out.append(f'            operation: "{namespace}.{opname}",')
    out.append(f"            method: .{HTTP_METHOD[op['method']]},")
    out.append(f'            template: "{op["path"]}",')
    out.append("            pathParameters: pathParameters,")
    out.append("            query: query,")
    out.append("            body: payload,")
    out.append("            scope: scope,")
    out.append(f"            implicitTenant: {'true' if 'tenant_id' in implicit else 'false'})")

    kind = op["response"]["kind"]
    schema = op["response"]["schema"]
    if kind == "none" or not schema:
        out.extend(comment(
            "A 204 carries no body. The bytes are read and dropped rather than ignored, so "
            "a server that started sending one does not silently change what this returns.",
            "        "))
        out.append("        _ = data")
    elif kind == "page":
        model = model_type(schema.lstrip("[]"))
        out.append(f"        return try ManagementCodec.decodePage({model}.self, "
                   "from: data, request: page)")
    elif kind == "array":
        model = model_type(schema.lstrip("[]"))
        out.append(f"        return try ManagementCodec.decode([{model}].self, from: data)")
    else:
        model = model_type(schema.lstrip("[]"))
        out.append(f"        return try ManagementCodec.decode({model}.self, from: data)")

    out.append("    }")
    out.append("")
    return out


HTTP_METHOD = {"GET": "get", "POST": "post", "PUT": "put", "PATCH": "patch",
               "DELETE": "delete"}


def emit_namespaces() -> str:
    """The 24 handles, their operations, and the accessors that put them on the client."""
    out = [BANNER, "import Foundation", ""]
    out.extend(comment(
        "CONTRACT.md §27 namespace handles — 147 operations across 24 of them.\n\n"
        "§27.2 rule 1: a handle is cheap and stateless. It holds the client and a scope of "
        "two optional strings, acquiring one performs no I/O, and every accessor below "
        "builds a fresh one — a caller cannot tell that from a memoized one, which is what "
        "the rule asks.\n\n"
        "§27.2 rule 3: the initializers are internal, so no handle is constructible without "
        "a client. There is no `RolesApi(baseURL:)` — that would be a second client with "
        "none of §3–§9's machinery attached.\n\n"
        "§27.8: every operation goes through `AxiamClient.managementSend`, which is the "
        "same request path §1 uses."))
    out.append("")

    for namespace, nsdef in REGISTRY["namespaces"].items():
        cls = handle_type(namespace)
        out.extend(doc(escape(nsdef.get("doc") or f"The `{namespace}` management namespace.")))
        out.append(f"public struct {cls}: Sendable {{")
        out.append("    private let client: AxiamClient")
        out.append("    private let scope: CallScope")
        out.append("")
        out.append("    init(client: AxiamClient, scope: CallScope) {")
        out.append("        self.client = client")
        out.append("        self.scope = scope")
        out.append("    }")
        out.append("")
        out.extend(doc(
            "This namespace scoped to a different organization (§27.4 rule 3).", "    "))
        out.extend(doc("", "    "))
        out.extend(doc(
            "Returns a NEW handle. A handle that repointed itself would mean an unrelated "
            "code path re-scoping a shared object could send this one's next WRITE to "
            "somebody else's organization.", "    "))
        out.append(f"    public func inOrg(_ orgID: String) -> {cls} {{")
        out.append(f"        {cls}(client: client, scope: scope.withOrg(orgID))")
        out.append("    }")
        out.append("")
        out.extend(doc("This namespace scoped to a different tenant (§27.4 rule 3).", "    "))
        out.extend(doc("", "    "))
        out.extend(doc("Returns a NEW handle, for the same reason `inOrg(_:)` does.", "    "))
        out.append(f"    public func forTenant(_ tenantID: String) -> {cls} {{")
        out.append(f"        {cls}(client: client, scope: scope.withTenant(tenantID))")
        out.append("    }")
        out.append("")
        for opname, op in nsdef["operations"].items():
            out.extend(emit_operation(namespace, opname, op))
        out.append("}")
        out.append("")

    # ---- the §27.2 rule 4 aggregate ----
    out.extend(doc("Every §27 namespace behind one accessor (§27.2 rule 4)."))
    out.extend(doc(""))
    out.extend(doc(
        "`client.management.users` and `client.users` are the same handle. This exists for "
        "callers who prefer the management surface not to be mixed in with §1's methods "
        "when reading a call site; rule 4 requires the two forms be equivalent, and they "
        "are because these delegate to the same initializer the direct accessors use."))
    out.append("public struct ManagementApi: Sendable {")
    out.append("    private let client: AxiamClient")
    out.append("    private let scope: CallScope")
    out.append("")
    out.append("    init(client: AxiamClient, scope: CallScope) {")
    out.append("        self.client = client")
    out.append("        self.scope = scope")
    out.append("    }")
    out.append("")
    for namespace, nsdef in REGISTRY["namespaces"].items():
        cls = handle_type(namespace)
        out.extend(doc(escape(nsdef.get("doc") or f"The `{namespace}` namespace."), "    "))
        out.append(f"    public var {prop(namespace)}: {cls} {{")
        out.append(f"        {cls}(client: client, scope: scope)")
        out.append("    }")
        out.append("")
    out.extend(doc("Declarative management — plan and apply a §27.6 manifest.", "    "))
    out.append("    public var manifest: ManifestApi {")
    out.append("        ManifestApi(client: client, scope: scope)")
    out.append("    }")
    out.append("}")
    out.append("")

    # ---- the accessors on the client ----
    out.extend(comment(
        "§27.2/§27.3: the namespace handles sit directly on the client — "
        "`client.serviceAccounts.rotateSecret(id)` is §27.3's Swift row verbatim. "
        "`client.management` above reaches the same handles behind one accessor.\n\n"
        "`nonisolated`, so reaching a handle is not itself an actor hop: "
        "`try await client.roles.list()` needs the one `await` the operation earns, not two. "
        "Nothing here touches isolated state — a handle is the client reference plus an "
        "empty scope, which is why acquiring one can perform no I/O (§27.2 rule 1)."))
    out.append("extension AxiamClient {")
    for namespace, nsdef in REGISTRY["namespaces"].items():
        cls = handle_type(namespace)
        out.extend(doc(escape(nsdef.get("doc") or f"The `{namespace}` namespace."), "    "))
        out.append(f"    public nonisolated var {prop(namespace)}: {cls} {{")
        out.append(f"        {cls}(client: self, scope: CallScope())")
        out.append("    }")
        out.append("")
    out.extend(doc("Every §27 namespace behind one accessor (§27.2 rule 4).", "    "))
    out.append("    public nonisolated var management: ManagementApi {")
    out.append("        ManagementApi(client: self, scope: CallScope())")
    out.append("    }")
    out.append("")
    out.extend(doc("Declarative management — plan and apply a §27.6 manifest.", "    "))
    out.append("    public nonisolated var manifest: ManifestApi {")
    out.append("        ManifestApi(client: self, scope: CallScope())")
    out.append("    }")
    out.append("}")
    return "\n".join(out).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Generated: conformance tests
# ---------------------------------------------------------------------------


def call_arguments(namespace: str, op: dict[str, Any]) -> str:
    """The argument list a generated test passes to one operation."""
    args = []
    for p in op_params(namespace, op):
        if p["kind"] == "path":
            args.append(f'{p["name"].strip("`")}: "{EXAMPLE_UUID}"')
        elif p["kind"] == "query" and p["required"]:
            args.append(f'{p["name"].strip("`")}: "example"')
        elif p["kind"] == "body":
            args.append(f'{p["name"]}: Self.{body_fixture_name(op)}')
    return ", ".join(args)


def body_fixture_name(op: dict[str, Any]) -> str:
    """The name of the decoded-from-JSON fixture a test passes as a request body."""
    return "fixture" + pascal(op["request_schema"].lstrip("[]"))


def emit_tests() -> str:
    """One conformance case per operation, per model and per enum."""
    out = [BANNER, "import XCTest", "@testable import AxiamSDK", ""]
    out.extend(comment(
        "CONTRACT.md §27 conformance — generated from the same registry the surface is.\n\n"
        "Three passes, each covering something the others structurally cannot see:\n\n"
        "1. Every operation reaches the METHOD and PATH the registry names, and its response "
        "decodes. The stub transport sits at the bottom of a REAL client, so an operation "
        "that opened its own request path would reach nothing (§27.8).\n"
        "2. Every model round-trips through JSON with exact equality against a wire object "
        "carrying every property the spec declares — so a dropped field and an invented one "
        "both fail. Pass 1 only ever DECODES, which is why a write-side omission needs its "
        "own assertion.\n"
        "3. Every enum maps both directions for every case, and an unrecognised value is "
        "REPORTED rather than silently becoming whichever case happens to be first.\n\n"
        "Generated by Scripts/gen_management.py; CI re-runs it with --check."))
    out.append("")

    # ---- request-body fixtures, decoded from the spec's own example shape ----
    bodies: dict[str, dict[str, Any]] = {}
    for namespace, nsdef in REGISTRY["namespaces"].items():
        for opname, op in nsdef["operations"].items():
            if op["request_body"] != "none" and op["request_schema"]:
                bodies[op["request_schema"].lstrip("[]")] = op

    out.append("final class ManagementGeneratedTests: XCTestCase {")
    out.append("")
    out.extend(comment(
        "Request bodies are DECODED from the spec's own example shape rather than built "
        "with memberwise initializers. A hand-written fixture drifts the moment a schema "
        "gains a required field: the generator would emit a model the fixture no longer "
        "satisfies, and the failure would be a compile error in a test file nobody "
        "associates with the registry. Decoding fails loudly instead, at the one line that "
        "names the schema.", "    "))
    out.append("")
    out.append("    static func decodeFixture<T: Decodable>(")
    out.append("        _ type: T.Type, _ json: String, _ schema: String")
    out.append("    ) -> T {")
    out.append("        do {")
    out.append("            return try JSONDecoder().decode(type, from: Data(json.utf8))")
    out.append("        } catch {")
    out.append("            fatalError(\"fixture for \\(schema) no longer matches its model: \\(error)\")")
    out.append("        }")
    out.append("    }")
    out.append("")
    for schema, op in sorted(bodies.items()):
        model = model_type(schema)
        example = example_for(schema)
        out.append(f"    static let {body_fixture_name(op)}: {model} = decodeFixture(")
        out.append(f"        {model}.self,")
        out.append(f"        {swift_string(json.dumps(example, sort_keys=True))},")
        out.append(f'        "{schema}")')
        out.append("")

    # ---- Pass 1: every operation reaches its route ----
    ops = 0
    for namespace, nsdef in REGISTRY["namespaces"].items():
        for opname, op in nsdef["operations"].items():
            ops += 1
            body = example_response(op)
            status = "200" if body is not None else "204"
            reply = swift_string(json.dumps(body)) if body is not None else '""'
            args = call_arguments(namespace, op)
            test_name = f"test{pascal(namespace)}{pascal(opname)}ReachesItsRoute"

            out.append(f"    func {test_name}() async throws {{")
            out.append(f"        let (client, transport) = try await ManagementFixture.signedIn(")
            out.append(f"            [(status: {status}, body: {reply})])")
            out.append(f"        _ = try await client.{prop(namespace)}.{method(opname)}({args})")
            out.append("")
            out.append("        XCTAssertEqual(transport.count, 1)")
            out.append(f'        XCTAssertEqual(transport.last?.method, "{op["method"]}")')
            out.append(f'        XCTAssertEqual(transport.last?.path, "{expected_path(op)}")')
            out.append("    }")
            out.append("")

    # ---- Pass 2: every model round-trips ----
    models = 0
    for name, rendered, _fields in modelled():
        example = example_for(name)
        if not isinstance(example, dict) or not example:
            # A model with no properties has nothing to lose in a round trip, and an
            # equality assertion over two empty objects asserts nothing.
            continue
        models += 1
        out.append(f"    func test{rendered}RoundTripsWithoutLosingAField() throws {{")
        out.append(f"        let json = {swift_string(json.dumps(example, sort_keys=True))}")
        out.append("        let wire = try XCTUnwrap(")
        out.append("            JSONSerialization.jsonObject(with: Data(json.utf8)) "
                   "as? [String: Any])")
        out.append("")
        out.append(f"        let value = try JSONDecoder().decode({rendered}.self, "
                   "from: Data(json.utf8))")
        out.append("        let encoded = try JSONEncoder().encode(value)")
        out.append("        let again = try XCTUnwrap(")
        out.append("            JSONSerialization.jsonObject(with: encoded) as? [String: Any])")
        out.append("")
        out.extend(comment(
            "Key-for-key, not \"the fields I remembered to check\". The wire object above "
            "carries every property the spec declares, so a dropped field and an invented "
            "one both fail here.", "        "))
        out.append("        XCTAssertEqual(Set(again.keys), Set(wire.keys))")
        out.append("        XCTAssertEqual(")
        out.append("            NSDictionary(dictionary: again), NSDictionary(dictionary: wire))")
        out.append("")
        out.extend(comment("And encoding is a fixed point — a second pass changes nothing.",
                           "        "))
        out.append(f"        let twice = try JSONEncoder().encode(")
        out.append(f"            try JSONDecoder().decode({rendered}.self, from: encoded))")
        out.append("        let third = try XCTUnwrap(")
        out.append("            JSONSerialization.jsonObject(with: twice) as? [String: Any])")
        out.append("        XCTAssertEqual(")
        out.append("            NSDictionary(dictionary: third), NSDictionary(dictionary: again))")
        out.append("    }")
        out.append("")

    # ---- Pass 3: every memberwise initializer assigns what it was given ----
    inits = 0
    for name, rendered, fields in modelled():
        example = example_for(name)
        if not isinstance(example, dict) or not example or not fields:
            continue
        inits += 1
        out.append(f"    func test{rendered}MemberwiseInitializerAssignsEveryProperty() throws {{")
        out.append(f"        let json = {swift_string(json.dumps(example, sort_keys=True))}")
        out.append(f"        let decoded = try JSONDecoder().decode({rendered}.self, "
                   "from: Data(json.utf8))")
        out.append("")
        out.extend(comment(
            "Every property handed straight back through the memberwise initializer. Two "
            "same-typed properties assigned to each other's stored property is a defect a "
            "decode-only test cannot see -- the JSON round trip above would pass, because "
            "it never constructs one by hand.", "        "))
        out.append(f"        let rebuilt = {rendered}(")
        args = [f"{f['name']}: decoded.{f['name']}" for f in fields]
        for i, arg in enumerate(args):
            out.append(f"            {arg}" + ("," if i < len(args) - 1 else ")"))
        out.append("")
        out.append("        let fromDecoded = try XCTUnwrap(JSONSerialization.jsonObject(")
        out.append("            with: try JSONEncoder().encode(decoded)) as? [String: Any])")
        out.append("        let fromRebuilt = try XCTUnwrap(JSONSerialization.jsonObject(")
        out.append("            with: try JSONEncoder().encode(rebuilt)) as? [String: Any])")
        out.append("        XCTAssertEqual(")
        out.append("            NSDictionary(dictionary: fromRebuilt),")
        out.append("            NSDictionary(dictionary: fromDecoded))")
        out.append("    }")
        out.append("")

    # ---- Pass 4: every enum maps both ways ----
    enums = 0
    for name in schema_closure():
        rendered = pascal(name)
        if rendered not in ENUMS:
            continue
        values = enum_values(name)
        if not values:
            continue
        enums += 1
        out.append(f"    func test{rendered}MapsEveryValueBothWays() throws {{")
        out.append(f"        XCTAssertEqual({rendered}.allCases.count, {len(values) + 1})")
        for value in values:
            case = enum_case(value)
            out.append(f'        XCTAssertEqual({rendered}.{case}.rawValue, "{value}")')
            out.append(f'        XCTAssertEqual({rendered}(rawValue: "{value}"), '
                       f"{rendered}.{case})")
        out.append("")
        out.extend(comment(
            "The raw-value initializer stays STRICT: an unrecognised value is nil, never "
            "whichever case happens to be first. Code that parses a raw string keeps its "
            "check.", "        "))
        out.append(f'        XCTAssertNil({rendered}(rawValue: "__not_a_{snake(rendered)}__"))')
        out.append("")
        out.extend(comment(
            "DECODING is the lenient direction, and only it (\u00a727.11 rule 1). Throwing "
            "here would fail the whole response the value arrived in, so one field of one "
            "record would take down the page it was on. `.unknown` is a case of its own and "
            "is never one of the known ones.", "        "))
        out.append(f'        let stranger = try JSONDecoder().decode(')
        out.append(f'            [{rendered}].self,')
        out.append(f'            from: Data("[\\"__not_a_{snake(rendered)}__\\"]".utf8))')
        out.append(f"        XCTAssertEqual(stranger, [{rendered}.unknown])")
        for value in values:
            out.append(f"        XCTAssertNotEqual({rendered}.unknown, "
                       f"{rendered}.{enum_case(value)})")
        out.append(f'        XCTAssertEqual({rendered}.unknown.rawValue, "")')
        first = enum_case(values[0])
        out.append(f'        let encoded = try JSONEncoder().encode([{rendered}.{first}])')
        out.append(f'        XCTAssertEqual(String(decoding: encoded, as: UTF8.self), '
                   f'"[\\"{values[0]}\\"]")')
        out.append("    }")
        out.append("")

    out.extend(comment(
        f"§27.9: this file covers {ops} operations, {models} models ({inits} of them also "
        f"through their memberwise initializer) and {enums} enums.\n\n"
        "The counts above are literals THIS generator wrote, so comparing them to each "
        "other would be a tautology a bad regeneration still satisfies. They are compared "
        "against the vendored registry instead, read at run time: if the registry gains an "
        "operation and nobody regenerates, the literal is stale and this fails — which is "
        "the same thing CI's drift-check job catches, asserted from inside the suite so it "
        "is also true for anyone running `swift test` locally.", "    "))
    out.append("    func testCoverageMatchesTheVendoredRegistry() throws {")
    out.append("        let root = URL(fileURLWithPath: #filePath)")
    out.append("            .deletingLastPathComponent()  // AxiamSDKTests")
    out.append("            .deletingLastPathComponent()  // Tests")
    out.append("            .deletingLastPathComponent()  // repository root")
    out.append('        let data = try Data(contentsOf: root'
               '.appendingPathComponent("management-registry.json"))')
    out.append("        let registry = try XCTUnwrap(")
    out.append("            JSONSerialization.jsonObject(with: data) as? [String: Any])")
    out.append('        let namespaces = try XCTUnwrap(registry["namespaces"] '
               "as? [String: [String: Any]])")
    out.append("")
    out.append("        let declared = namespaces.values.reduce(into: 0) { total, namespace in")
    out.append('            total += (namespace["operations"] as? [String: Any])?.count ?? 0')
    out.append("        }")
    out.append(f"        XCTAssertEqual(declared, {ops},")
    out.append('                       "the registry declares a different number of operations '
               'than this file covers — regenerate with Scripts/gen_management.py")')
    out.append(f"        XCTAssertEqual(namespaces.count, "
               f"{len(REGISTRY['namespaces'])})")
    out.append("    }")
    out.append("}")
    return "\n".join(out).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def build() -> dict[Path, str]:
    """Every file this generator owns, keyed by absolute path."""
    files = {
        MODELS_SWIFT: emit_models(),
        OPS_SWIFT: emit_namespaces(),
        TESTS_SWIFT: emit_tests(),
    }
    return {ROOT / path: text for path, text in files.items()}


def main() -> int:
    """Write (or, with ``--check``, verify) the generated §27 surface."""
    # Reject an unrecognised flag rather than ignoring it. The failure this guards against
    # is a CI job that means to VERIFY and instead REGENERATES silently — a typo in the flag
    # would turn the drift gate into a no-op that reports success, which is the one outcome
    # worse than having no gate at all.
    unknown = [a for a in sys.argv[1:] if a != "--check"]
    if unknown:
        print(f"unrecognised argument(s): {' '.join(unknown)}", file=sys.stderr)
        print("usage: gen_management.py [--check]", file=sys.stderr)
        return 2

    check = "--check" in sys.argv
    files = build()

    if check:
        drifted = [p for p, text in sorted(files.items())
                   if not p.exists() or p.read_text() != text]
        if drifted:
            for path in drifted:
                print(f"out of date: {path.relative_to(ROOT)}", file=sys.stderr)
            print(
                "\nThe committed §27 surface disagrees with management-registry.json / "
                "openapi.json.\nRegenerate with `python3 Scripts/gen_management.py` and "
                "commit the result.",
                file=sys.stderr,
            )
            return 1
        print(f"§27 surface is current ({len(files)} files).")
        return 0

    for path, text in sorted(files.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    print(f"wrote {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
