"""Standardised API error envelope (Drips Wave #159 contract)."""

from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

ERROR_CODES = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    422: "VALIDATION_ERROR",
    500: "INTERNAL_ERROR",
    502: "DEPENDENCY_UNAVAILABLE",
    503: "SERVICE_UNAVAILABLE",
}


def dependency_unavailable_error(
    dependency: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    """Return a structured 503 DEPENDENCY_UNAVAILABLE response envelope."""
    merged_details = {"dependency": dependency, **(details or {})}
    return JSONResponse(
        status_code=503,
        content={
            "status": "not_ready",
            "database": "ok",
            dependency: "unavailable",
            **error_body("DEPENDENCY_UNAVAILABLE", message, details=merged_details),
        },
    )


def error_body(code: str, message: str, details: Any = None) -> dict:
    body: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return body


def api_error(status_code: int, code: str, message: str, details: Any = None) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=error_body(code, message, details))


async def http_exception_handler(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict) and "code" in exc.detail:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})

    code = ERROR_CODES.get(exc.status_code, "BAD_REQUEST")
    message = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return api_error(exc.status_code, code, message)


async def validation_exception_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    return api_error(
        422,
        "VALIDATION_ERROR",
        "Request validation failed",
        details=exc.errors(),
    )


async def unhandled_exception_handler(_request: Request, _exc: Exception) -> JSONResponse:
    return api_error(500, "INTERNAL_ERROR", "An unexpected error occurred")


def raise_api_error(status_code: int, code: str, message: str, details: Any = None) -> None:
    from fastapi import HTTPException

    payload: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        payload["details"] = details
    raise HTTPException(status_code=status_code, detail=payload)
