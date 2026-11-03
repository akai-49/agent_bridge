"""HTTP client helper for claude-bridge relay communication.

Provides retry logic with exponential backoff for Render cold starts (waking services).
Python 3.9 compatible, stdlib only.
"""
from __future__ import annotations
import http.client
import time
from typing import Callable, Sequence, Union
import urllib.error
import urllib.request

DEFAULT_TIMEOUT = 70.0
DEFAULT_BACKOFFS: tuple[float, ...] = (3.0, 6.0, 12.0)
RETRY_STATUS_CODES = frozenset({502, 503, 504})


def relay_urlopen(
    req: Union[urllib.request.Request, str],
    timeout: float = DEFAULT_TIMEOUT,
    backoffs: Sequence[float] = DEFAULT_BACKOFFS,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> http.client.HTTPResponse:
    """Execute an HTTP request with retries on connection errors and 502/503/504.

    Retries up to len(backoffs) times using the backoff delays in seconds.
    Never retries 4xx client errors (raises immediately).
    """
    max_retries = len(backoffs)
    attempt = 0

    while True:
        try:
            return urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code in RETRY_STATUS_CODES and attempt < max_retries:
                delay = backoffs[attempt]
                attempt += 1
                try:
                    e.read()
                    e.close()
                except Exception:
                    pass
                sleep_fn(delay)
                continue
            raise
        except (
            urllib.error.URLError,
            ConnectionError,
            TimeoutError,
            OSError,
            http.client.RemoteDisconnected,
        ) as e:
            if attempt < max_retries:
                delay = backoffs[attempt]
                attempt += 1
                sleep_fn(delay)
                continue
            raise
