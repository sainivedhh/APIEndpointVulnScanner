"""
sender.py - HTTP Request Sender with Rate Limiting and Safe Mode

Responsible for dispatching mutated tokens to the target API endpoint
and collecting raw HTTP responses for analysis.
"""

import time
import json
import asyncio
from typing import Optional, Dict, Any, List

import requests
import aiohttp
from requests.exceptions import RequestException, Timeout, ConnectionError
from rich.console import Console

console = Console()


class RequestSender:
    """
    Sends HTTP requests with authentication tokens and collects responses.

    Supports JWT (Bearer header) and HMAC (Authorization header or custom)
    token delivery. Implements rate limiting and timeout management.
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        rate_limit: float = 1.0,
        verbose: bool = False,
        user_agent: str = "APIScannerResearch/1.0 (Authorized Security Research)",
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        auth_header_name: str = "Authorization"
    ):
        """
        Initialize the request sender.

        Args:
            base_url: Target base URL
            timeout: Request timeout in seconds
            rate_limit: Seconds to wait between requests (0 = no limit)
            verbose: Print request/response details
            user_agent: Custom User-Agent header
            proxy: Proxy URL to route traffic through
            verify_ssl: Boolean representing enforcing SSL verifications
            auth_header_name: Custom authentication header
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.auth_header_name = auth_header_name
        self._last_request_time = 0.0

        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "application/json, */*",
        })

    def _rate_limit_sleep(self):
        """Enforce rate limiting between requests."""
        if self.rate_limit > 0:
            elapsed = time.time() - self._last_request_time
            sleep_time = self.rate_limit - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)
        self._last_request_time = time.time()

    def _build_headers(
        self,
        token: str,
        token_type: str,
        extra_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Build request headers with the given token.

        JWT tokens → Authorization: Bearer <token>
        HMAC tokens → Authorization: HMAC <token>

        Args:
            token: The (possibly mutated) token string
            token_type: 'jwt' or 'hmac'
            extra_headers: Additional headers to include

        Returns:
            Complete headers dictionary
        """
        headers = {}
        if token_type == "jwt":
            headers[self.auth_header_name] = f"Bearer {token}"
            headers["Content-Type"] = "application/json"
        elif token_type == "hmac":
            headers[self.auth_header_name] = f"HMAC {token}"
            headers["Content-Type"] = "application/json"

        if extra_headers:
            headers.update(extra_headers)
        return headers

    def send(
        self,
        url: str,
        method: str = "GET",
        token: str = "",
        token_type: str = "jwt",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Send an HTTP request with the given token.

        Args:
            url: Full URL to request
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            token: Authentication token
            token_type: Type of token ('jwt' or 'hmac')
            headers: Additional headers
            body: Request body for POST/PUT requests

        Returns:
            Dictionary with response metadata, or None if request failed
        """
        self._rate_limit_sleep()

        req_headers = self._build_headers(token, token_type, headers)
        method = method.upper()

        if self.verbose:
            console.print(f"[dim]→ {method} {url}[/dim]")
            console.print(f"[dim]  Auth: {req_headers.get(self.auth_header_name, '')[:60]}...[/dim]")

        start_time = time.time()
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=req_headers,
                json=body,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl,
            )
            elapsed_ms = (time.time() - start_time) * 1000

            # Parse response body
            response_body = None
            try:
                response_body = response.json()
            except (ValueError, Exception):
                response_body = {"raw": response.text[:2000]}

            result = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response_body,
                "raw_body": response.text[:5000],
                "response_time_ms": elapsed_ms,
                "url": url,
                "method": method,
                "token_used": token[:50] + ("..." if len(token) > 50 else ""),
                "request_headers": req_headers,
            }

            if self.verbose:
                console.print(f"[dim]  ← HTTP {response.status_code} ({elapsed_ms:.0f}ms)[/dim]")

            return result

        except Timeout:
            if self.verbose:
                console.print(f"[yellow]  ⚠ Timeout after {self.timeout}s[/yellow]")
            return {
                "status_code": 0,
                "error": "timeout",
                "response_time_ms": self.timeout * 1000,
                "url": url,
                "method": method,
                "token_used": token[:50],
                "headers": {},
                "body": None,
                "raw_body": "",
                "request_headers": req_headers,
            }
        except ConnectionError as e:
            if self.verbose:
                console.print(f"[red]  ✗ Connection error: {str(e)[:80]}[/red]")
            return None
        except RequestException as e:
            if self.verbose:
                console.print(f"[red]  ✗ Request failed: {str(e)[:80]}[/red]")
            return None

    def send_with_cookie(
        self,
        url: str,
        method: str = "GET",
        token: str = "",
        cookie_name: str = "token",
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Send request with token in Cookie header instead of Authorization.

        Args:
            url: Target URL
            method: HTTP method
            token: Token value
            cookie_name: Name of the cookie (default: 'token')
            extra_headers: Additional headers

        Returns:
            Response dictionary
        """
        self._rate_limit_sleep()
        headers = extra_headers or {}
        headers["Cookie"] = f"{cookie_name}={token}"

        start_time = time.time()
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=self.verify_ssl,
            )
            elapsed_ms = (time.time() - start_time) * 1000
            try:
                body = response.json()
            except Exception:
                body = {"raw": response.text[:2000]}

            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": body,
                "raw_body": response.text[:5000],
                "response_time_ms": elapsed_ms,
                "url": url,
                "method": method,
                "token_used": token[:50],
                "request_headers": headers,
            }
        except Exception:
            return None


class AsyncRequestSender:
    """
    Asynchronous version of RequestSender using aiohttp.
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        rate_limit: float = 0.0,
        verbose: bool = False,
        user_agent: str = "APIScannerResearch/1.0 (Async)",
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        auth_header_name: str = "Authorization"
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.auth_header_name = auth_header_name
        self.proxy = proxy
        
        self.headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json, */*",
        }

    async def send(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str = "GET",
        token: str = "",
        token_type: str = "jwt",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Send an asynchronous HTTP request."""
        
        # Build headers
        req_headers = {}
        if token_type == "jwt":
            req_headers[self.auth_header_name] = f"Bearer {token}"
            req_headers["Content-Type"] = "application/json"
        elif token_type == "hmac":
            req_headers[self.auth_header_name] = f"HMAC {token}"
            req_headers["Content-Type"] = "application/json"

        if headers:
            req_headers.update(headers)

        method = method.upper()
        if self.verbose:
            console.print(f"[dim]→ (Async) {method} {url}[/dim]")

        start_time = time.time()
        try:
            async with session.request(
                method=method,
                url=url,
                headers=req_headers,
                json=body,
                timeout=self.timeout,
                proxy=self.proxy,
                ssl=self.verify_ssl
            ) as response:
                elapsed_ms = (time.time() - start_time) * 1000
                
                text = await response.text()
                try:
                    response_body = await response.json()
                except Exception:
                    response_body = {"raw": text[:2000]}

                result = {
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "body": response_body,
                    "raw_body": text[:5000],
                    "response_time_ms": elapsed_ms,
                    "url": url,
                    "method": method,
                    "token_used": token[:50] + ("..." if len(token) > 50 else ""),
                    "request_headers": req_headers,
                }

                if self.verbose:
                    console.print(f"[dim]  ← HTTP {response.status} ({elapsed_ms:.0f}ms)[/dim]")

                return result

        except asyncio.TimeoutError:
            return {
                "status_code": 0,
                "error": "timeout",
                "response_time_ms": self.timeout.total * 1000 if self.timeout.total else 0,
                "url": url,
                "method": method,
                "token_used": token[:50],
                "headers": {},
                "body": None,
                "raw_body": "",
                "request_headers": req_headers,
            }
        except Exception as e:
            if self.verbose:
                console.print(f"[red]  ✗ Async request failed: {str(e)[:80]}[/red]")
            return None
