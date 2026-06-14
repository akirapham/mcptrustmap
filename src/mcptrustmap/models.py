"""Core data models (dataclasses).

The deterministic core uses stdlib dataclasses only — no pydantic, no network.
Pydantic is reserved for the optional reasoning layer's structured outputs.
Every model round-trips through `to_dict`/`from_dict` so records and reports are
schema-validatable at the boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ArgRecord:
    """A single tool argument and the security role it plays."""

    name: str
    json_type: str | None = None
    role: str = "unknown"  # assigned by evidence.roles (Phase 2)
    constrained: bool = False  # enum/pattern/format/min-max present?
    schema_path: str = ""  # evidence anchor, e.g. "properties/path"
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "json_type": self.json_type,
            "role": self.role,
            "constrained": self.constrained,
            "schema_path": self.schema_path,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ArgRecord:
        return cls(
            name=d["name"],
            json_type=d.get("json_type"),
            role=d.get("role", "unknown"),
            constrained=bool(d.get("constrained", False)),
            schema_path=d.get("schema_path", ""),
            description=d.get("description"),
        )


@dataclass
class InferredAuthority:
    """An authority class inferred from source, with its provenance and anchor."""

    authority: str
    sub_source: str  # "ast" | "regex" | "llm"
    anchor: str  # "file:line" or "schema-path"
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority": self.authority,
            "sub_source": self.sub_source,
            "anchor": self.anchor,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> InferredAuthority:
        return cls(
            authority=d["authority"],
            sub_source=d["sub_source"],
            anchor=d["anchor"],
            detail=d.get("detail", ""),
        )


@dataclass
class ToolRecord:
    """A single MCP tool: its declaration and (later) its inferred authority."""

    name: str
    description: str | None = None
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)
    arguments: list[ArgRecord] = field(default_factory=list)
    declared_authority: list[str] = field(default_factory=list)
    inferred_authority: list[InferredAuthority] = field(default_factory=list)
    source_symbol: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "annotations": self.annotations,
            "arguments": [a.to_dict() for a in self.arguments],
            "declared_authority": self.declared_authority,
            "inferred_authority": [i.to_dict() for i in self.inferred_authority],
            "source_symbol": self.source_symbol,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ToolRecord:
        return cls(
            name=d["name"],
            description=d.get("description"),
            input_schema=d.get("input_schema", {}),
            annotations=d.get("annotations", {}),
            arguments=[ArgRecord.from_dict(a) for a in d.get("arguments", [])],
            declared_authority=list(d.get("declared_authority", [])),
            inferred_authority=[
                InferredAuthority.from_dict(i) for i in d.get("inferred_authority", [])
            ],
            source_symbol=d.get("source_symbol"),
        )


@dataclass
class OAuthConfig:
    """OAuth/proxy configuration extracted from a server (the authz audit input)."""

    client_id: str | None = None
    redirect_uris: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    is_proxy: bool = False
    token_endpoint: str | None = None
    redirect_match: str | None = None  # "exact" | "prefix" | "wildcard"
    forwards_token: bool | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "redirect_uris": self.redirect_uris,
            "scopes": self.scopes,
            "is_proxy": self.is_proxy,
            "token_endpoint": self.token_endpoint,
            "redirect_match": self.redirect_match,
            "forwards_token": self.forwards_token,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> OAuthConfig:
        return cls(
            client_id=d.get("client_id"),
            redirect_uris=list(d.get("redirect_uris", [])),
            scopes=list(d.get("scopes", [])),
            is_proxy=bool(d.get("is_proxy", False)),
            token_endpoint=d.get("token_endpoint"),
            redirect_match=d.get("redirect_match"),
            forwards_token=d.get("forwards_token"),
            raw=d.get("raw", {}),
        )


@dataclass
class Finding:
    """A reported finding. Evidence is a resolved anchor, never LLM prose."""

    finding_id: str
    severity: str  # critical|high|medium|low|info
    owasp: str  # MCP01..MCP10
    title: str
    server_id: str
    evidence: list[dict[str, Any]]  # [{kind, ref, detail}]
    recommendation: str
    confidence: str  # high|medium|low
    provenance: str  # deterministic|llm-verified
    status: str = "reproduced"  # reproduced|not_applicable
    spec_ref: str | None = None
    tool: str | None = None
    argument: str | None = None
    sub_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "owasp": self.owasp,
            "title": self.title,
            "server_id": self.server_id,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "provenance": self.provenance,
            "status": self.status,
        }
        for key in ("spec_ref", "tool", "argument", "sub_type"):
            value = getattr(self, key)
            if value is not None:
                d[key] = value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        return cls(
            finding_id=d["finding_id"],
            severity=d["severity"],
            owasp=d["owasp"],
            title=d["title"],
            server_id=d["server_id"],
            evidence=list(d.get("evidence", [])),
            recommendation=d["recommendation"],
            confidence=d["confidence"],
            provenance=d["provenance"],
            status=d.get("status", "reproduced"),
            spec_ref=d.get("spec_ref"),
            tool=d.get("tool"),
            argument=d.get("argument"),
            sub_type=d.get("sub_type"),
        )

    @property
    def dedup_key(self) -> tuple[str, str, str, str]:
        anchors = ";".join(sorted(e.get("ref", "") for e in self.evidence))
        return (self.finding_id, self.server_id, self.tool or "", anchors)


@dataclass
class ServerRecord:
    """A configured MCP server: how it launches, its tools, its auth surface."""

    server_id: str
    client: str  # claude_desktop|cursor|windsurf|vscode_cline|generic
    transport: str  # stdio|http|sse
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    package: str | None = None  # npx/uvx/pip launch spec (supply chain)
    source_path: str | None = None
    oauth: OAuthConfig | None = None
    tools: list[ToolRecord] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "client": self.client,
            "transport": self.transport,
            "command": self.command,
            "args": self.args,
            "env": self.env,
            "url": self.url,
            "package": self.package,
            "source_path": self.source_path,
            "oauth": self.oauth.to_dict() if self.oauth else None,
            "tools": [t.to_dict() for t in self.tools],
            "resources": self.resources,
            "prompts": self.prompts,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ServerRecord:
        oauth = d.get("oauth")
        return cls(
            server_id=d["server_id"],
            client=d["client"],
            transport=d["transport"],
            command=d.get("command"),
            args=list(d.get("args", [])),
            env=dict(d.get("env", {})),
            url=d.get("url"),
            package=d.get("package"),
            source_path=d.get("source_path"),
            oauth=OAuthConfig.from_dict(oauth) if oauth else None,
            tools=[ToolRecord.from_dict(t) for t in d.get("tools", [])],
            resources=list(d.get("resources", [])),
            prompts=list(d.get("prompts", [])),
        )
