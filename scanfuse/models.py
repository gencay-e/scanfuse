from pydantic import BaseModel, Field, field_validator


def location_label(method: str | None, location: str | None) -> str:
    """Text for a location as shown in reports, e.g. 'POST /account [id parameter]'."""
    return " ".join(part for part in (method, location) if part)


class Host(BaseModel):
    ip: str
    hostname: str | None = None
    os: str | None = None
    port: int | None = None


def host_key(host: Host) -> str | None:
    """How an observation names a host: the IP, or the host name if the IP is not known."""
    ip = (host.ip or "").strip()
    if ip and ip.lower() != "unknown":
        return ip
    return (host.hostname or "").strip() or None


class Observation(BaseModel):
    """One place where one tool saw a finding: a host, and for web findings a method and location."""
    host: str | None = Field(default=None, description="IP or host name, as in `hosts`. None if the tool names none.")
    method: str | None = Field(default=None, description="HTTP method, upper case.")
    location: str | None = Field(
        default=None,
        description="URL path, with the parameter if the tool names one (e.g. '/search [q parameter]'). Case-sensitive.",
    )
    source_tool: str

    @field_validator("host", "location")
    @classmethod
    def _strip(cls, value: str | None) -> str | None:
        # URL paths and parameter names are case-sensitive: only surrounding space is removed.
        return (value or "").strip() or None

    @field_validator("method")
    @classmethod
    def _normalize_method(cls, value: str | None) -> str | None:
        return (value or "").strip().upper() or None

    def place(self) -> tuple[str | None, str | None]:
        return (self.method, self.location)

    def label(self) -> str:
        """Host, method and location as one line, e.g. '10.0.0.1 POST /account'."""
        return " ".join(part for part in (self.host, self.method, self.location) if part)


class Evidence(BaseModel):
    type: str = Field(..., description="e.g., 'http-request', 'port-scan'")
    data: str = Field(..., description="The raw evidence payload or output")
    code: str | None = Field(default=None, description="Code snippet or source line")
    source: str | None = Field(
        default=None,
        description="Tool that reported this evidence. Set when findings of several tools are merged.",
    )
    hosts: list[str] = Field(
        default_factory=list,
        description="Hosts this evidence belongs to. Set when findings are merged; empty if it cannot be attributed.",
    )


class SourceRecord(BaseModel):
    """What one tool reported for a finding. Kept when findings are merged."""
    source_tool: str
    title: str
    severity: str = Field(..., pattern="^(Critical|High|Medium|Low|Info)$")
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    description: str
    remediation: str | None = None
    identifiers: list[str] = Field(default_factory=list)
    port: str | None = None


class Finding(BaseModel):
    title: str
    severity: str = Field(..., pattern="^(Critical|High|Medium|Low|Info)$")
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    description: str
    remediation: str | None = None
    hosts: list[Host] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    source_tool: str = Field(..., description="e.g., 'nmap', 'nuclei'")
    slug: str | None = None
    identifiers: list[str] = Field(
        default_factory=list,
        description="CVE/GHSA ids and tool ids such as 'nessus-plugin:12345' or 'CWE-89'",
    )
    references: list[str] = Field(default_factory=list, description="http(s) links the scanner gives for this finding")
    port: str | None = Field(default=None, description="e.g. '443/tcp'")
    observations: list[Observation] = Field(
        default_factory=list,
        description="Where each tool saw this finding: host, and for web findings method and location.",
    )
    sources: list[SourceRecord] = Field(
        default_factory=list,
        description="One record per merged finding. Empty if the finding was not merged.",
    )
    tags: list[str] = Field(default_factory=list)
    cvss_merge_conflict: bool = Field(
        default=False,
        description="True when merged findings had incompatible CVSS vectors (different base metrics)",
    )

    def places(self) -> frozenset[tuple[str | None, str | None]]:
        """The (method, location) pairs of the observations. Part of the merge identity."""
        return frozenset(o.place() for o in self.observations if o.method or o.location)

    def affected(self) -> list[str]:
        """Affected host, method and location lines as shown in reports. Observations that
        name only a host are not listed: the hosts have their own section."""
        return list(dict.fromkeys(o.label() for o in self.observations if o.method or o.location))

    def place_labels(self) -> list[str]:
        """Distinct method and location pairs without the host, e.g. 'POST /account'."""
        return list(dict.fromkeys(
            location_label(o.method, o.location)
            for o in self.observations if o.method or o.location
        ))


class Report(BaseModel):
    title: str
    findings: list[Finding] = Field(default_factory=list)
