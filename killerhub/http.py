from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Mapping

import requests


@dataclass
class HttpClient:
    timeout: float
    delay: float
    user_agent: str

    def __post_init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        self._last_request_at = 0.0

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        data: Mapping[str, str] | None = None,
    ) -> requests.Response | None:
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)

        try:
            response = self.session.request(
                method,
                url,
                params=params,
                data=data,
                timeout=self.timeout,
                allow_redirects=True,
            )
            self._last_request_at = time.monotonic()
            return response
        except requests.RequestException:
            self._last_request_at = time.monotonic()
            return None

