from pydantic import BaseModel, Field
class LoginIn(BaseModel): username: str; password: str
class MfaVerifyIn(BaseModel): challenge: str=''; code: str
class MfaCodeIn(BaseModel): code: str
class EventIn(BaseModel): asset_ip: str=''; source: str; event_type: str; severity: str; title: str; detail: str=''
class IncidentIn(BaseModel): title: str; severity: str='MEDIUM'; summary: str=''; owner: str=''
class PlaybookIn(BaseModel): incident_id: int; name: str; action_type: str; target: str=''; notes: str=''
class VulnerabilityIn(BaseModel):
    asset_ip: str; cve_id: str; product: str=''; installed_version: str=''; fixed_version: str=''; cvss: float=Field(0,ge=0,le=10); kev: bool=False; severity: str='MEDIUM'; source: str='MANUAL'; notes: str=''
class IdentityIn(BaseModel): observed_mac: str=''; observed_hostname: str=''
class TcpProbeIn(BaseModel): ports: list[int]=[22,80,443,445,3389]
class PatchIn(BaseModel):
    asset_ip: str; patch_name: str; cve_id: str=''; status: str='PENDING'; due_date: str=''; owner: str=''; notes: str=''
class PatchStatusIn(BaseModel): status: str; notes: str=''
class ComplianceUpdateIn(BaseModel): status: str; evidence: str=''; owner: str=''
