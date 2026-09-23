"""Unified application errors and error handlers."""

import logging
from typing import Any, Optional
from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("cyberguard.errors")


class AppError(Exception):
    """Base application exception."""

    def __init__(
        self,
        message: str,
        code: str = "app_error",
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Optional[Any] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details


class NotFoundError(AppError):
    def __init__(self, resource: str, identifier: str = ""):
        message = f"{resource} not found" if not identifier else f"{resource} '{identifier}' not found"
        super().__init__(message, code="not_found", status_code=status.HTTP_404_NOT_FOUND)


class UnauthorizedError(AppError):
    def __init__(self, message: str = "Missing or invalid credentials"):
        super().__init__(message, code="unauthorized", status_code=status.HTTP_401_UNAUTHORIZED)


class PermissionDeniedError(AppError):
    def __init__(self, message: str = "You do not have permission to perform this action"):
        super().__init__(message, code="permission_denied", status_code=status.HTTP_403_FORBIDDEN)


class ValidationError(AppError):
    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(message, code="validation_error", status_code=status.HTTP_400_BAD_REQUEST, details=details)


class ConflictError(AppError):
    def __init__(self, message: str):
        super().__init__(message, code="conflict", status_code=status.HTTP_409_CONFLICT)


class EmailExistsError(AppError):
    def __init__(
        self,
        message: str = "An account with this email already exists.",
        hint: str = "sign_in",
    ):
        super().__init__(message, code="email_exists", status_code=status.HTTP_409_CONFLICT)
        self.hint = hint


class AccountTypeMismatchError(AppError):
    def __init__(
        self,
        message: str = "This email is registered as an organization account. Please sign in using Organization mode.",
        hint: str = "use_org_mode",
    ):
        super().__init__(
            message=message,
            code="account_type_mismatch",
            status_code=status.HTTP_403_FORBIDDEN,
        )
        self.hint = hint


class ExternalServiceError(AppError):
    def __init__(self, service: str, message: str):
        super().__init__(
            f"External service error ({service}): {message}",
            code="external_service_error",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class NonRetryableError(AppError):
    """Exception indicating a permanent failure that should not be retried (poison pill protection)."""

    def __init__(self, message: str, reason: str = "non_retryable", details: Optional[Any] = None):
        super().__init__(message, code=reason, status_code=status.HTTP_400_BAD_REQUEST, details=details)
        self.reason = reason


# ---------------------------------------------------------------------------
# Attachment scanning errors (ATTACH-SCAN)
# ---------------------------------------------------------------------------

class AttachmentTooLargeError(AppError):
    """Attachment exceeds MAX_ATTACHMENT_SIZE_BYTES."""

    def __init__(self, message: str = "Attachment exceeds the maximum allowed size"):
        super().__init__(message, code="attachment_too_large", status_code=413)


class UnsupportedFileTypeError(AppError):
    """Attachment type is not in SUPPORTED_MIME_TYPES."""

    def __init__(self, message: str = "Attachment file type is not supported"):
        super().__init__(message, code="unsupported_file_type", status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)


class ScanTimeoutError(AppError):
    """Attachment scan exceeded its allowed time budget."""

    def __init__(self, message: str = "Attachment scan timed out"):
        super().__init__(message, code="scan_timeout", status_code=status.HTTP_504_GATEWAY_TIMEOUT)


class MemoryLimitExceededError(AppError):
    """Worker memory crossed MEMORY_CRITICAL_THRESHOLD_MB during scanning."""

    def __init__(self, message: str = "Attachment scan aborted: memory limit exceeded"):
        super().__init__(message, code="memory_limit_exceeded", status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


class ArchiveDepthExceededError(AppError):
    """Nested archive exceeded MAX_ARCHIVE_DEPTH (Phase 2 archive inspection)."""

    def __init__(self, message: str = "Archive nesting depth exceeds the allowed limit"):
        super().__init__(message, code="archive_depth_exceeded", status_code=status.HTTP_400_BAD_REQUEST)



class ComingSoonError(StarletteHTTPException):
    """Frozen-feature marker rendered with the plain FastAPI detail envelope.

    Raised by require_org_enabled: 501 {"detail": "Organization accounts are
    coming soon."}
    """

    def __init__(self, message: str):
        super().__init__(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=message)


def register_error_handlers(app: FastAPI) -> None:
    """Register unified exception handlers on the FastAPI app."""

    @app.exception_handler(AppError)
    async def app_error_handler(_request: Request, exc: AppError) -> JSONResponse:
        content = {
            "error": exc.code,
            "message": exc.message,
        }
        if hasattr(exc, "hint") and getattr(exc, "hint") is not None:
            content["hint"] = exc.hint
        if exc.details is not None:
            content["details"] = jsonable_encoder(exc.details)
        return JSONResponse(status_code=exc.status_code, content=content)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        status_code = (
            status.HTTP_422_UNPROCESSABLE_ENTITY
            if request.url.path.startswith("/api/v1/p/")
            else status.HTTP_400_BAD_REQUEST
        )
        return JSONResponse(
            status_code=status_code,
            content={
                "error": "invalid_payload",
                "message": "Request payload failed validation.",
                "details": jsonable_encoder(exc.errors()),
            },
        )

    @app.exception_handler(IntegrityError)
    async def integrity_error_handler(_request: Request, exc: IntegrityError) -> JSONResponse:
        logger.warning("Database integrity error: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "error": "conflict_error",
                "message": "Database constraint violation or conflict.",
            },
        )

    @app.exception_handler(SQLAlchemyError)
    async def sqlalchemy_error_handler(_request: Request, exc: SQLAlchemyError) -> JSONResponse:
        logger.exception("Database error occurred: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "database_error",
                "message": "A database error occurred while processing the request.",
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "http_error",
                "message": exc.detail if isinstance(exc.detail, str) else "HTTP exception",
                "details": exc.detail if not isinstance(exc.detail, str) else None,
            },
        )

    @app.exception_handler(ComingSoonError)
    async def coming_soon_handler(_request: Request, exc: ComingSoonError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error on %s %s: %s", request.method, request.url.path, exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "internal_server_error",
                "message": "An unexpected error occurred. Please try again later.",
            },
        )
