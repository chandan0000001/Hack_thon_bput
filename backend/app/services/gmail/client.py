"""Async Gmail API client with OAuth2 error handling and token refresh."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import httpx

from app.services.connectors import oauth_service

logger = logging.getLogger("cyberguard.gmail.client")

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"


class GmailClientError(Exception):
    """Base exception for Gmail API client errors."""

    def __init__(self, message: str, status_code: Optional[int] = None, details: Any = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details


class GmailAuthError(GmailClientError):
    """401 Unauthorized - authentication failure or expired credentials."""


class GmailScopeError(GmailClientError):
    """403 Forbidden - insufficient OAuth scope or access denied."""


class GmailRateLimitError(GmailClientError):
    """429 Too Many Requests - Gmail API rate limits exceeded."""


class GmailServerError(GmailClientError):
    """5xx Server Error - transient Google backend failure."""


class HistoryResult(list):
    """List of Gmail history entries with attached history_id metadata."""

    def __init__(self, items: list[dict[str, Any]], history_id: Optional[str] = None):
        super().__init__(items)
        self.history_id = history_id


class GmailClient:
    """Async wrapper over Gmail API."""

    def __init__(
        self,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = 15.0,
    ):
        self._client = client
        self._timeout = timeout
        self.last_refreshed_access_token: Optional[str] = None

    def _map_error(self, status_code: int, details: Any) -> GmailClientError:
        message = f"Gmail API error (HTTP {status_code})"
        if isinstance(details, dict) and "error" in details:
            err_info = details["error"]
            if isinstance(err_info, dict) and "message" in err_info:
                message = f"Gmail API error ({status_code}): {err_info['message']}"

        if status_code == 401:
            return GmailAuthError(message, status_code=status_code, details=details)
        if status_code == 403:
            return GmailScopeError(message, status_code=status_code, details=details)
        if status_code == 429:
            return GmailRateLimitError(message, status_code=status_code, details=details)
        if 500 <= status_code <= 599:
            return GmailServerError(message, status_code=status_code, details=details)
        return GmailClientError(message, status_code=status_code, details=details)

    async def _request(
        self,
        method: str,
        url: str,
        access_token: str,
        refresh_token: Optional[str] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Perform an authorized request with single-retry token refresh on 401."""
        req_timeout = kwargs.pop("timeout", self._timeout)
        headers = dict(kwargs.pop("headers", {}))
        headers["Authorization"] = f"Bearer {access_token}"

        async def _execute(tok: str) -> httpx.Response:
            h = dict(headers)
            h["Authorization"] = f"Bearer {tok}"
            if self._client is not None:
                return await self._client.request(method, url, headers=h, **kwargs)
            async with httpx.AsyncClient(timeout=req_timeout) as client:
                return await client.request(method, url, headers=h, **kwargs)

        try:
            response = await _execute(access_token)
        except (httpx.TimeoutException, asyncio.TimeoutError) as exc:
            logger.warning("Gmail API request timeout: %s", exc)
            raise GmailServerError(f"Gmail request timeout: {exc}", status_code=504) from exc

        # Token refresh on 401 if refresh_token is available
        if response.status_code == 401 and refresh_token:
            logger.info("Gmail request returned 401; attempting token refresh")
            try:
                refreshed = await oauth_service.refresh_token(refresh_token)
                new_token = refreshed.get("access_token")
                if new_token:
                    self.last_refreshed_access_token = new_token
                    response = await _execute(new_token)
            except Exception as exc:
                logger.warning("Token refresh failed during 401 retry: %s", exc)
                raise GmailAuthError(
                    f"Authentication failed (401) and token refresh failed: {exc}",
                    status_code=401,
                ) from exc

        try:
            data = response.json() if response.content else {}
        except Exception:
            data = {"raw_text": response.text}

        if response.status_code != 200:
            raise self._map_error(response.status_code, data)

        return data

    async def list_history(
        self,
        access_token: str,
        start_history_id: str | int,
        refresh_token: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Call GET https://gmail.googleapis.com/gmail/v1/users/me/history?startHistoryId={start_history_id}.

        Returns list of history records with top-level history_id attached.
        """
        url = f"{GMAIL_API_BASE}/users/me/history?startHistoryId={start_history_id}"
        data = await self._request("GET", url, access_token, refresh_token=refresh_token)
        history_items = data.get("history", [])
        top_history_id = data.get("historyId")
        return HistoryResult(history_items, history_id=top_history_id)

    async def list_messages(
        self,
        access_token: str,
        q: str = "in:inbox",
        max_results: int = 10,
        refresh_token: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Call GET https://gmail.googleapis.com/gmail/v1/users/me/messages?q={q}&maxResults={max_results}."""
        url = f"{GMAIL_API_BASE}/users/me/messages?q={q}&maxResults={max_results}"
        data = await self._request("GET", url, access_token, refresh_token=refresh_token)
        return data.get("messages", [])

    async def get_profile(
        self,
        access_token: str,
        refresh_token: Optional[str] = None,
    ) -> dict[str, Any]:
        """Call GET https://gmail.googleapis.com/gmail/v1/users/me/profile."""
        url = f"{GMAIL_API_BASE}/users/me/profile"
        return await self._request("GET", url, access_token, refresh_token=refresh_token)

    async def get_message(
        self,
        access_token: str,
        message_id: str,
        format: str = "full",
        timeout: Optional[float] = None,
        refresh_token: Optional[str] = None,
    ) -> dict[str, Any]:
        """Call GET https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?format={format}."""
        url = f"{GMAIL_API_BASE}/users/me/messages/{message_id}?format={format}"
        req_kwargs: dict[str, Any] = {}
        if timeout is not None:
            req_kwargs["timeout"] = timeout
        return await self._request("GET", url, access_token, refresh_token=refresh_token, **req_kwargs)

    async def stream_attachment(
        self,
        message_id: str,
        attachment_id: str,
        chunk_size: int = 65536,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ):
        """Stream an attachment's bytes in chunks without buffering it fully in memory.

        GET https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}/attachments/{attachment_id}
        Yields raw byte chunks of at most chunk_size. Unlike the JSON methods,
        the response body is consumed as a stream so large attachments never
        materialize as a single in-memory object.
        """
        if not access_token:
            raise GmailAuthError("stream_attachment requires an access token", status_code=401)

        url = f"{GMAIL_API_BASE}/users/me/messages/{message_id}/attachments/{attachment_id}"

        if self._client is not None:
            client, owns_client = self._client, False
        else:
            client, owns_client = httpx.AsyncClient(timeout=self._timeout), True

        try:
            token = access_token
            async with client.stream("GET", url, headers={"Authorization": f"Bearer {token}"}) as response:
                if response.status_code == 401 and refresh_token:
                    logger.info("Gmail attachment stream returned 401; attempting token refresh")
                    refreshed = await oauth_service.refresh_token(refresh_token)
                    token = refreshed.get("access_token") or token
                    if owns_client:
                        await response.aclose()
                    async with client.stream(
                        "GET", url, headers={"Authorization": f"Bearer {token}"}
                    ) as retry_response:
                        retry_response.raise_for_status()
                        async for chunk in retry_response.aiter_bytes(chunk_size=chunk_size):
                            yield chunk
                    return

                response.raise_for_status()
                async for chunk in response.aiter_bytes(chunk_size=chunk_size):
                    yield chunk
        except httpx.TimeoutException as exc:
            raise GmailServerError(f"Gmail attachment stream timeout: {exc}", status_code=504) from exc
        finally:
            if owns_client:
                await client.aclose()

    async def watch(
        self,
        access_token: str,
        topic: str,
        labels: Optional[list[str]] = None,
        refresh_token: Optional[str] = None,
    ) -> dict[str, Any]:
        """Call POST https://gmail.googleapis.com/gmail/v1/users/me/watch.

        Registers Gmail mailbox push notifications to the configured Google Cloud Pub/Sub topic.
        Returns dict with historyId and expiration timestamp (epoch milliseconds).
        """
        url = f"{GMAIL_API_BASE}/users/me/watch"
        payload: dict[str, Any] = {
            "topicName": topic,
            "labelIds": labels if labels is not None else ["INBOX"],
        }
        return await self._request("POST", url, access_token, refresh_token=refresh_token, json=payload)

    async def stop_watch(
        self,
        access_token: str,
        refresh_token: Optional[str] = None,
    ) -> dict[str, Any]:
        """Call POST https://gmail.googleapis.com/gmail/v1/users/me/stop.

        Stops Gmail mailbox push notifications for the authenticated user.
        """
        url = f"{GMAIL_API_BASE}/users/me/stop"
        return await self._request("POST", url, access_token, refresh_token=refresh_token)

