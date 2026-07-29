from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .errors import IntelligenceLimitError, IntelligenceTransportError

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_MODIFIED_INDEX_URL = "https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv"
OSV_API_BASE_URL = "https://api.osv.dev/v1/vulns/"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
DEFAULT_USER_AGENT = "white-hat-agent-public-intelligence/1 (+https://github.com/kappa9999/white-hat-agent)"


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str
    complete: bool = True
    line_count: int | None = None

    def header(self, name: str) -> str | None:
        wanted = name.casefold()
        return next((value for key, value in self.headers.items() if key.casefold() == wanted), None)


class HttpTransport(Protocol):
    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
        max_bytes: int,
    ) -> HttpResponse: ...


class UrllibHttpTransport:
    """Bounded GET-only transport restricted to the intelligence providers."""

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
        max_bytes: int,
    ) -> HttpResponse:
        _validate_official_url(url)
        if max_bytes < 1:
            raise IntelligenceLimitError("response byte limit must be positive")
        request_headers = {str(key): str(value) for key, value in headers.items()}
        if not any(key.casefold() == "user-agent" for key in request_headers):
            raise IntelligenceTransportError("HTTP request requires an explicit User-Agent")
        request = Request(url, headers=request_headers, method="GET")
        try:
            response = _open(request, timeout=timeout)
        except HTTPError as exc:
            with exc:
                return self._read_response(exc, requested_url=url, max_bytes=max_bytes)
        except (TimeoutError, URLError, OSError) as exc:
            raise IntelligenceTransportError(
                f"public source request failed: {type(exc).__name__}", retriable=True
            ) from exc
        with response:
            return self._read_response(response, requested_url=url, max_bytes=max_bytes)

    def get_until_line(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
        max_bytes: int,
        max_lines: int,
        max_line_bytes: int,
        stop_after: Callable[[bytes], bool],
    ) -> HttpResponse:
        """Stream a line-oriented response and close it at a caller-defined boundary."""

        _validate_official_url(url)
        if min(max_bytes, max_lines, max_line_bytes) < 1:
            raise IntelligenceLimitError("stream limits must be positive")
        request_headers = {str(key): str(value) for key, value in headers.items()}
        if not any(key.casefold() == "user-agent" for key in request_headers):
            raise IntelligenceTransportError("HTTP request requires an explicit User-Agent")
        request = Request(url, headers=request_headers, method="GET")
        try:
            response = _open(request, timeout=timeout)
        except HTTPError as exc:
            with exc:
                return self._read_response(exc, requested_url=url, max_bytes=max_bytes)
        except (TimeoutError, URLError, OSError) as exc:
            raise IntelligenceTransportError(
                f"public source request failed: {type(exc).__name__}", retriable=True
            ) from exc
        with response:
            final_url = response.geturl() or url
            _validate_official_url(final_url)
            chunks: list[bytes] = []
            byte_length = 0
            line_count = 0
            complete = True
            while True:
                line = response.readline(max_line_bytes + 1)
                if not line:
                    break
                line_count += 1
                if line_count > max_lines:
                    raise IntelligenceLimitError(f"public source stream exceeds {max_lines} line limit")
                if len(line) > max_line_bytes:
                    raise IntelligenceLimitError(
                        f"public source stream line exceeds {max_line_bytes} byte limit"
                    )
                byte_length += len(line)
                if byte_length > max_bytes:
                    raise IntelligenceLimitError(f"public source stream exceeds {max_bytes} byte limit")
                chunks.append(line)
                if stop_after(line):
                    complete = False
                    break
            return HttpResponse(
                status=int(response.status),
                headers={str(key): str(value) for key, value in response.headers.items()},
                body=b"".join(chunks),
                url=final_url,
                complete=complete,
                line_count=line_count,
            )

    @staticmethod
    def _read_response(response, *, requested_url: str, max_bytes: int) -> HttpResponse:
        final_url = response.geturl() or requested_url
        _validate_official_url(final_url)
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                declared_length = -1
            if declared_length > max_bytes:
                raise IntelligenceLimitError(f"public source response exceeds {max_bytes} byte limit")
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise IntelligenceLimitError(f"public source response exceeds {max_bytes} byte limit")
        return HttpResponse(
            status=int(response.status),
            headers={str(key): str(value) for key, value in response.headers.items()},
            body=body,
            url=final_url,
        )


def _validate_official_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
        raise IntelligenceTransportError("public source URL is not an allowed HTTPS endpoint")
    host = (parsed.hostname or "").casefold()
    path = parsed.path
    allowed = (
        (
            host == "www.cisa.gov"
            and path == "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            and not parsed.query
        )
        or (
            host == "osv-vulnerabilities.storage.googleapis.com"
            and path == "/modified_id.csv"
            and not parsed.query
        )
        or (
            host == "api.osv.dev"
            and path.startswith("/v1/vulns/")
            and bool(path.removeprefix("/v1/vulns/"))
            and "/" not in path.removeprefix("/v1/vulns/")
            and "%2f" not in path.casefold()
            and not parsed.query
        )
        or (host == "api.first.org" and path == "/data/v1/epss")
    )
    if not allowed:
        raise IntelligenceTransportError("public source URL is outside the official allowlist")


class _AllowlistedRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_official_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(request: Request, *, timeout: float):
    opener = build_opener(_AllowlistedRedirectHandler())
    return opener.open(request, timeout=timeout)
