from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .errors import IntelligenceLimitError, IntelligenceTransportError

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_LIST_V5_DELTA_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
CVE_LIST_V5_RECORD_BASE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"
OSV_MODIFIED_INDEX_URL = "https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv"
OSV_API_BASE_URL = "https://api.osv.dev/v1/vulns/"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_USER_AGENT = "white-hat-agent-public-intelligence/1 (+https://github.com/kappa9999/white-hat-agent)"

_CVE_LIST_V5_RECORD_PATH = re.compile(
    r"^/CVEProject/cvelistV5/main/cves/\d{4}/\d+xxx/CVE-\d{4}-\d{4,}\.json$"
)


def nvd_cve_api_url(
    start: datetime,
    end: datetime,
    *,
    results_per_page: int,
    start_index: int,
) -> str:
    """Build the one supported NVD API 2.0 incremental request shape."""

    if start.tzinfo is None or end.tzinfo is None or start > end:
        raise ValueError("NVD window requires ordered timezone-aware datetimes")
    if end - start > timedelta(days=120):
        raise ValueError("NVD last-modified windows cannot exceed 120 days")
    if not 1 <= results_per_page <= 2_000:
        raise ValueError("NVD results_per_page must be between 1 and 2000")
    if start_index < 0:
        raise ValueError("NVD start_index cannot be negative")
    query = urlencode(
        (
            ("lastModStartDate", _nvd_datetime(start)),
            ("lastModEndDate", _nvd_datetime(end)),
            ("resultsPerPage", str(results_per_page)),
            ("startIndex", str(start_index)),
        )
    )
    return f"{NVD_CVE_API_URL}?{query}"


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
            host == "raw.githubusercontent.com"
            and (
                path == "/CVEProject/cvelistV5/main/cves/deltaLog.json"
                or _CVE_LIST_V5_RECORD_PATH.fullmatch(path) is not None
            )
            and "%" not in path
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
        or (
            host == "services.nvd.nist.gov"
            and path == "/rest/json/cves/2.0"
            and _is_allowed_nvd_query(parsed.query)
        )
    )
    if not allowed:
        raise IntelligenceTransportError("public source URL is outside the official allowlist")


def _nvd_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _is_allowed_nvd_query(query: str) -> bool:
    if not query or len(query) > 2_000:
        return False
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return False
    if len(pairs) != 4 or len({key for key, _ in pairs}) != 4:
        return False
    values = dict(pairs)
    if set(values) != {"lastModStartDate", "lastModEndDate", "resultsPerPage", "startIndex"}:
        return False
    try:
        start = _parse_nvd_datetime(values["lastModStartDate"])
        end = _parse_nvd_datetime(values["lastModEndDate"])
        results_per_page = int(values["resultsPerPage"])
        start_index = int(values["startIndex"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        start <= end
        and end - start <= timedelta(days=120)
        and 1 <= results_per_page <= 2_000
        and start_index >= 0
        and str(results_per_page) == values["resultsPerPage"]
        and str(start_index) == values["startIndex"]
    )


def _parse_nvd_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    if parsed.tzinfo is None:
        raise ValueError("NVD datetime must include a timezone")
    return parsed.astimezone(UTC)


class _AllowlistedRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_official_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(request: Request, *, timeout: float):
    opener = build_opener(_AllowlistedRedirectHandler())
    return opener.open(request, timeout=timeout)
