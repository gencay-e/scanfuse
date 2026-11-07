
from pydantic import BaseModel, Field


class Host(BaseModel):
    ip: str
    hostname: str | None = None
    os: str | None = None

class Evidence(BaseModel):
    type: str = Field(..., description="e.g., 'http-request', 'port-scan'")
    data: str = Field(..., description="The raw evidence payload or output")
    source: str | None = Field(
        default=None,
        description="Tool that reported this evidence. Set when findings of several tools are merged.",
    )

class SourceRecord(BaseModel):
    """What one tool reported for a finding. Kept when findings are merged."""
    source_tool: str
    title: str
    severity: str = Field(..., pattern="^(Critical|High|Medium|Low|Info)$")
    cvss_score: float | None = None
    cvss_vector: str | None = None
    description: str
    remediation: str | None = None
    identifiers: list[str] = Field(default_factory=list)
    port: str | None = None

class Finding(BaseModel):
    title: str
    severity: str = Field(..., pattern="^(Critical|High|Medium|Low|Info)$")
    cvss_score: float | None = None
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
    sources: list[SourceRecord] = Field(
        default_factory=list,
        description="One record per merged finding. Empty if the finding was not merged.",
    )

class Report(BaseModel):
    title: str
    findings: list[Finding] = Field(default_factory=list)
