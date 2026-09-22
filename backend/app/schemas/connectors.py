"""Schemas for email connector endpoints. No token material ever appears."""

from typing import Any, Optional

from pydantic import BaseModel


class ConnectorCapability(BaseModel):
    read_messages: bool
    read_attachments: bool
    modify_labels: bool
    quarantine: bool
    trash: bool
    permanent_delete: bool
    sender_rules: bool
    send_mail: bool
    unsupported_reason: Optional[str] = None


class ConnectorAccountRead(BaseModel):
    id: str
    provider: str
    provider_email: str
    status: str
    scopes: list[str] = []
    capabilities: dict[str, Any] = {}
    last_test_at: Optional[str] = None
    last_sync_at: Optional[str] = None
    last_error: Optional[str] = None
    created_at: Optional[str] = None


class ConnectorListResponse(BaseModel):
    items: list[ConnectorAccountRead]


class ConnectorAuthorizeRequest(BaseModel):
    redirect_after: Optional[str] = None
    reconnect: Optional[str] = None


class ConnectorAuthorizeResponse(BaseModel):
    authorization_url: str


class GmailAccountItem(BaseModel):
    id: str
    email: str
    status: str
    disconnected_at: Optional[str] = None
    paused_at: Optional[str] = None
    last_push_at: Optional[str] = None
    removes_at: Optional[str] = None
    created_at: Optional[str] = None
    last_sync_at: Optional[str] = None
    sync_status: Optional[str] = None
    last_error: Optional[str] = None


class GmailAccountsListResponse(BaseModel):
    connected: list[GmailAccountItem]
    recent: list[GmailAccountItem]


class GmailActionResponse(BaseModel):
    success: bool
    message: str
    status: str
    account_id: Optional[str] = None
    id: Optional[str] = None
    gap_job_id: Optional[str] = None



class ConnectorTestResponse(BaseModel):
    ok: bool
    provider: Optional[str] = None
    email_address: Optional[str] = None
    messages_total: Optional[int] = None
    error_class: Optional[str] = None
    message: Optional[str] = None


class ConnectorDisconnectResponse(BaseModel):
    id: str
    status: str


class ConnectorOperationRead(BaseModel):
    id: str
    connector_id: Optional[str] = None
    provider: str
    operation: str
    status: str
    message: Optional[str] = None
    provider_error_code: Optional[str] = None
    created_at: Optional[str] = None


class ConnectorOperationListResponse(BaseModel):
    items: list[ConnectorOperationRead]


class ProviderRegistryEntryRead(BaseModel):
    provider: str
    display_name: str
    status: str  # enabled | coming_soon | unsupported
    capabilities: Optional[ConnectorCapability] = None
    detail: str = ""


class ConnectorCapabilitiesResponse(BaseModel):
    items: list[ProviderRegistryEntryRead]
